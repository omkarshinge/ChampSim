/*************************************************************************************************************************
Authors:
Samuel Pakalapati - samuelpakalapati@gmail.com
Biswabandan Panda - biswap@cse.iitk.ac.in
Nilay Shah - nilays@iitk.ac.in
Neelu Shivprakash kalani - neeluk@cse.iitk.ac.in
**************************************************************************************************************************/

/*************************************************************************************************************************
Source code of "Bouquet of Instruction Pointers: Instruction Pointer Classifier-based Spatial Hardware Prefetching"
appeared (to appear) in ISCA 2020: https://www.iscaconf.org/isca2020/program/. The paper is available at
https://www.cse.iitk.ac.in/users/biswap/IPCP_ISCA20.pdf. The source code can be used with the ChampSim simulator
https://github.com/ChampSim . Note that the authors have used a modified ChampSim that supports detailed virtual
memory sub-system. Performance numbers may increase/decrease marginally
based on the virtual memory-subsystem support. Also for PIPT L1-D caches, this code may demand 1 to 1.5KB additional
storage for various hardware tables.
**************************************************************************************************************************/

#include "ipcp.h"

#include <iostream>
#include <random>
#include <vector>

#include "cache.h"
#include "ipcp_table_sizes.h"

/**************************************************************************************************************************
Note that variables uint64_t pref_useful[6], pref_filled[6], pref_late[6]; are to be declared
as members of the CACHE class in inc/cache.h and modified in src/cache.cc where the second level index denotes the IPCP prefetch
class type for each variable which can be extracted through pf_metadata. A prefetch is considered in pref_useful when a cache
blocks gets a hit and its prefetch bit is set. Whenever a cache block is filled (in handle_fill) and its type is prefetch,
pref_fill is incremented. The pref_late variable is modified whenever a demand request merges with a prefetch request or
vice versa in the cache's MSHR as, if the prefetch would've been on time, the demand request would've hit in the cache.
****************************************************************************************************************************/

// #define CRITICAL_IP_PREF

#define PREF_CLASS_MASK 0xF00 // 0x1E000	//IPCP pref class
#define NUM_OF_STRIDE_BITS 8  // 13	//IPCP stride

#define DO_PREF
#define NUM_BLOOM_ENTRIES 4096 // For book-keeping purposes
#define NUM_IP_TAG_BITS 9
#define NUM_PAGE_TAG_BITS 2
#define S_TYPE 1    // stream
#define CS_TYPE 2   // constant stride
#define CPLX_TYPE 3 // complex stride
#define NL_TYPE 4   // next line
#define CPLX_DIST 0
#define RR_TAG_MASK 0xFFF // 12 bits of prefetch line address are stored in recent request filter
#define NUM_OF_RR_ENTRIES 32
#define MAX_POS_NEG_COUNT 64      // 6-bit saturating counter
#define NUM_OF_LINES_IN_REGION 32 // 32 cache lines in 2KB region
#define REGION_OFFSET_MASK 0x1F   // 5-bit offset for 2KB region

// #define SIG_DEBUG_PRINT				    // Uncomment to turn on Debug Print
#ifdef SIG_DEBUG_PRINT
#define SIG_DP(x) x
#else
#define SIG_DP(x)
#endif

enum IPCP_CLASSES { NL = 1, GS, CS, CPLX, SEQ, RCTP };

/*
 * RCTP related structures
 *
 * */

#define RCTP_REGION_SIZE 4096 // 4KB per region

// Entry to track region metadata
struct RegionEntry {
  uint64_t region_tag;
  std::vector<int64_t> deltas;
  std::vector<uint64_t> offsets; // New field: track offsets inside region
  uint64_t last_access_cycle;
};

std::unordered_map<uint64_t, RegionEntry> region_table; // Map of region tag → RegionEntry

// Distance Accuracy Table (DAT)
std::unordered_map<int64_t, int> distance_accuracy_table; // region distance -> accuracy counter

/*
 * Sequitur related structures
 *
 * */

// Custom hash function for std::pair (no Boost needed)
struct pair_hash {
  template <class T1, class T2>
  std::size_t operator()(const std::pair<T1, T2>& p) const
  {
    auto h1 = std::hash<T1>{}(p.first);
    auto h2 = std::hash<T2>{}(p.second);
    return h1 ^ (h2 << 1);
  }
};

class SequiturPredictor
{
public:
  struct Rule {
    std::vector<int64_t> sequence;
  };

  std::vector<int64_t> history_buffer;
  std::unordered_map<std::pair<int64_t, int64_t>, int, pair_hash> digram_count;
  std::unordered_map<uint64_t, Rule> grammar_rules;

  void feed_delta(int64_t delta)
  {
    history_buffer.push_back(delta);

    // Limit history buffer to 64 entries
    if (history_buffer.size() > 64) {
      history_buffer.erase(history_buffer.begin());
    }

    if (history_buffer.size() >= 2) {
      auto pair = std::make_pair(history_buffer[history_buffer.size() - 2], history_buffer.back());
      digram_count[pair]++;

      // If digram_count becomes too large, clear it
      if (digram_count.size() > 256) {
        digram_count.clear(); // simple reset
      }

      if (digram_count[pair] > 2) {
        grammar_rules[dhash(pair)] = {{pair.first, pair.second}};
      }
    }
  }

  std::vector<int64_t> predict_next()
  {
    if (history_buffer.empty())
      return {};

    const int MAX_CHAIN_LENGTH = 4; // Limit maximum prefetch chain steps
    int64_t current_delta = history_buffer.back();
    std::vector<int64_t> predictions;
    int chain_steps = 0;

    while (chain_steps < MAX_CHAIN_LENGTH) {
      std::vector<int64_t> best_sequence;
      size_t best_length = 0;

      // Find the best matching rule starting with current_delta
      for (auto& rule : grammar_rules) {
        if (!rule.second.sequence.empty() && rule.second.sequence.front() == current_delta) {
          if (rule.second.sequence.size() > best_length) {
            best_sequence = rule.second.sequence;
            best_length = rule.second.sequence.size();
          }
        }
      }

      // If no matching rule found, stop chaining
      if (best_sequence.empty()) {
        break;
      }

      // Append predicted deltas (excluding first element which matched current_delta)
      for (size_t i = 1; i < best_sequence.size() && chain_steps < MAX_CHAIN_LENGTH; ++i) {
        predictions.push_back(best_sequence[i]);
        current_delta = best_sequence[i];
        chain_steps++;
      }
    }

    return predictions;
  }

private:
  uint64_t dhash(const std::pair<int64_t, int64_t>& p) const { return ((uint64_t)p.first << 32) | (uint64_t)p.second; }
};

SequiturPredictor sequitur_predictor;
int pf_cs = 0, pf_nl = 0, pf_gs = 0, pf_cplx = 0, pf_seq = 0, pf_rctp = 0;
int pf_cs_useful = 0, pf_nl_useful = 0, pf_gs_useful = 0, pf_cplx_useful = 0, pf_seq_useful = 0, pf_rctp_useful = 0;
int pf_cs_not_useful = 0, pf_nl_not_useful = 0, pf_gs_not_useful = 0, pf_cplx_not_useful = 0, pf_seq_not_useful = 0, pf_rctp_not_useful = 0;
int pf_cs_hit = 0, pf_nl_hit = 0, pf_gs_hit = 0, pf_cplx_hit = 0;
int pf_cs_fill = 0, pf_nl_fill = 0, pf_gs_fill = 0, pf_cplx_fill = 0, pf_seq_fill = 0, pf_rctp_fill = 0;
int pf_cs_lc = 0, pf_nl_lc = 0, pf_gs_lc = 0, pf_cplx_lc = 0, pf_seq_lc = 0, pf_rctp_lc = 0;

int conf_nl = 0;
int conf_gs = 0;
int conf_cs = 0;
int conf_cplx = 0;
int conf_seq = 0;
int conf_rctp = 0;

void update_class_confidences()
{
  if ((pf_nl_useful + 5) > pf_nl_not_useful)
    conf_nl++;
  else
    conf_nl--;
  if ((pf_gs_useful + 5) > pf_gs_not_useful)
    conf_gs++;
  else
    conf_gs--;
  if ((pf_cs_useful + 5) > pf_cs_not_useful)
    conf_cs++;
  else
    conf_cs--;
  if ((pf_cplx_useful + 5) > pf_cplx_not_useful)
    conf_cplx++;
  else
    conf_cplx--;
  if ((pf_seq_useful + 5) > pf_seq_not_useful)
    conf_seq++;
  else
    conf_seq--;
  if ((pf_rctp_useful + 5) > pf_rctp_not_useful)
    conf_rctp++;
  else
    conf_rctp--;

  // Clamp confidence within [-5, +5]
  conf_nl = std::clamp(conf_nl, -5, 5);
  conf_gs = std::clamp(conf_gs, -5, 5);
  conf_cs = std::clamp(conf_cs, -5, 5);
  conf_cplx = std::clamp(conf_cplx, -5, 5);
  conf_seq = std::clamp(conf_seq, -5, 5);
  conf_rctp = std::clamp(conf_rctp, -5, 5);

  // Reset per-class useful and not-useful counters after update
  pf_nl_useful = pf_nl_not_useful = 0;
  pf_gs_useful = pf_gs_not_useful = 0;
  pf_cs_useful = pf_cs_not_useful = 0;
  pf_cplx_useful = pf_cplx_not_useful = 0;
  pf_seq_useful = pf_seq_not_useful = 0;
  pf_rctp_useful = pf_rctp_not_useful = 0;
}
/**
 *
 * Reinforcement Learning Q values based
 *
 *  */

bool enable_seq, enable_rctp, enable_gs, enable_cs, enable_cplx, enable_nl;

class PrefetcherQLearningController
{

public:
  static constexpr int NUM_MSHR_BINS = 3;
  static constexpr int NUM_PFQ_BINS = 3;
  static constexpr int NUM_USE_CS_BINS = 2;
  static constexpr int NUM_USE_GS_BINS = 2;
  static constexpr int NUM_USE_NL_BINS = 2;
  static constexpr int NUM_USE_CPLX_BINS = 2;

  static constexpr int NUM_STATES = NUM_MSHR_BINS * NUM_PFQ_BINS * NUM_USE_CS_BINS * NUM_USE_GS_BINS * NUM_USE_NL_BINS * NUM_USE_CPLX_BINS; // 144 states
  static constexpr int NUM_ACTIONS = 32;

  int8_t Q[NUM_STATES][NUM_ACTIONS];

  const float alpha = 0.2f;
  const float gamma = 0.9f;
  float epsilon = 1.0f;

  PrefetcherQLearningController()
  {
    for (int s = 0; s < NUM_STATES; ++s) {
      for (int a = 0; a < NUM_ACTIONS; ++a) {
        Q[s][a] = 10;
      }
    }
  }

  int quantize_mshr(float mshr_ratio)
  {
    if (mshr_ratio < 0.4f)
      return 0;
    else if (mshr_ratio < 0.75f)
      return 1;
    else
      return 2;
  }

  int quantize_pfq(float pfq_ratio)
  {
    if (pfq_ratio < 0.4f)
      return 0;
    else if (pfq_ratio < 0.75f)
      return 1;
    else
      return 2;
  }

  int quantize_usefulness_class(int useful, int not_useful)
  {
    int total = useful + not_useful;
    if (total == 0)
      return 0;
    return (useful * 100 / total >= 25) ? 1 : 0;
  }

  int quantize_usefulness_cs() { return quantize_usefulness_class(pf_cs_useful, pf_cs_not_useful); }
  int quantize_usefulness_gs() { return quantize_usefulness_class(pf_gs_useful, pf_gs_not_useful); }
  int quantize_usefulness_nl() { return quantize_usefulness_class(pf_nl_useful, pf_nl_not_useful); }
  int quantize_usefulness_cplx() { return quantize_usefulness_class(pf_cplx_useful, pf_cplx_not_useful); }

  int get_state_index(int mshr_bin, int pfq_bin, int cs_bin, int gs_bin, int nl_bin, int cplx_bin)
  {
    return (((((mshr_bin * NUM_PFQ_BINS + pfq_bin) * NUM_USE_CS_BINS + cs_bin) * NUM_USE_GS_BINS + gs_bin) * NUM_USE_NL_BINS + nl_bin) * NUM_USE_CPLX_BINS
            + cplx_bin);
  }

  int select_action(int state)
  {
    if ((float)(rand() % 100) / 100.0f < epsilon) {
      return (rand() % 8) + 8;
    } else {
      int best_action = 0;
      int8_t best_q = Q[state][0];
      for (int a = 1; a < NUM_ACTIONS; ++a) {
        if (Q[state][a] > best_q) {
          best_q = Q[state][a];
          best_action = a;
        }
      }
      return best_action;
    }
  }

  void update_q_table(int old_state, int action, float reward, int new_state)
  {
    int8_t max_future_q = *std::max_element(Q[new_state], Q[new_state] + NUM_ACTIONS);
    int8_t current_q = Q[old_state][action];
    int scaled_reward = static_cast<int>(reward * 127.0f);

    int update = static_cast<int>(current_q + alpha * (scaled_reward + gamma * max_future_q - current_q));
    update = std::clamp(update, -128, 127);
    Q[old_state][action] = static_cast<int8_t>(update);
  }

  float calculate_reward(int useful_prefetches, int not_useful_prefetches)
  {
    int total = useful_prefetches + not_useful_prefetches;
    if (total == 0)
      return 0.0f;
    return static_cast<float>((useful_prefetches) + 10) / (total + 10);
  }
};

uint64_t last_decision_cycle = 0;
const uint64_t decision_interval = 10000; // every 10K cycles

int last_state = 0;
int last_action = 0;

// Prefetch usefulness tracking (reset every interval)
int useful_prefetches_last_interval = 0;
int total_prefetches_last_interval = 0;

PrefetcherQLearningController ql_controller;

struct ClassControl {
  bool enabled;
  int prefetch_degree;
};

ClassControl class_control_nl;
ClassControl class_control_gs;
ClassControl class_control_cs;
ClassControl class_control_cplx;
ClassControl class_control_seq;
ClassControl class_control_rctp;
struct PrefetchAction {
  int action_nl;   // Next-Line prefetch control
  int action_gs;   // Global Stream prefetch control
  int action_cs;   // Constant Stride prefetch control
  int action_cplx; // Complex Stride prefetch control
  int action_seq;  // Sequitur prefetch control
  int action_rctp; // RCTP prefetch control
};
PrefetchAction decode_action(int action_id)
{
  // static const int action_table[16][6] = {{0, 0, 0, 0, 0, 0}, {1, 1, 1, 0, 0, 1}, {2, 2, 2, 0, 0, 2}, {3, 3, 3, 0, 0, 3},
  //                                         {1, 0, 0, 0, 2, 2}, {2, 0, 0, 0, 3, 3}, {0, 1, 0, 0, 1, 1}, {0, 2, 1, 0, 2, 2},
  //                                         {0, 0, 1, 1, 2, 3}, {1, 2, 2, 2, 1, 1}, {1, 3, 3, 0, 2, 2}, {0, 1, 0, 1, 3, 2},
  //                                         {2, 2, 2, 2, 1, 1}, {3, 1, 0, 1, 1, 3}, {1, 0, 0, 0, 1, 3}, {3, 0, 0, 0, 0, 2}};

  // const int action_table[16][6] = {
  //     // NL, GS, CS, CPLX, SEQ, RCTP
  //     {0, 0, 0, 0, 0, 0}, // Action 0: Everything OFF
  //     {1, 1, 1, 0, 0, 0}, // Action 1: Light NL+GS+CS
  //     {2, 2, 2, 0, 0, 0}, // Action 2: Medium NL+GS+CS
  //     {3, 3, 3, 0, 0, 0}, // Action 3: Heavy NL+GS+CS
  //     {1, 0, 0, 1, 0, 0}, // Action 4: Light NL + CPLX
  //     {2, 0, 0, 2, 0, 0}, // Action 5: Medium NL + CPLX
  //     {0, 1, 0, 1, 0, 0}, // Action 6: Light GS + CPLX
  //     {0, 2, 1, 2, 0, 0}, // Action 7: Medium GS + CS + CPLX
  //     {1, 1, 2, 0, 0, 0}, // Action 8: NL + GS + stronger CS
  //     {1, 2, 2, 0, 0, 0}, // Action 9: NL + strong GS + CS
  //     {2, 2, 1, 1, 0, 0}, // Action 10: balanced NL+GS, weaker CPLX
  //     {1, 3, 0, 1, 0, 0}, // Action 11: light NL + aggressive GS + CPLX
  //     {2, 1, 2, 0, 0, 0}, // Action 12: stronger CS with moderate NL/GS
  //     {3, 1, 1, 0, 0, 0}, // Action 13: heavy NL, light GS
  //     {1, 0, 2, 0, 0, 0}, // Action 14: NL + strong CS
  //     {3, 0, 1, 0, 0, 0}  // Action 15: heavy NL + light CS
  // };

  static const int action_table[32][6] = {
      //  NL,  GS,  CS, CPLX, SEQ, RCTP
      {0, 0, 0, 0, 0, 0}, // 0: all off
      {1, 0, 0, 0, 0, 0}, // 1: light NL
      {2, 0, 0, 0, 0, 0}, // 2: moderate NL
      {3, 0, 0, 0, 0, 0}, // 3: aggressive NL

      {0, 1, 0, 0, 0, 0}, // 4: light GS
      {0, 2, 0, 0, 0, 0}, // 5: moderate GS
      {0, 3, 0, 0, 0, 0}, // 6: aggressive GS

      {0, 0, 1, 0, 0, 0}, // 7: light CS
      {0, 0, 2, 0, 0, 0}, // 8: moderate CS
      {0, 0, 3, 0, 0, 0}, // 9: aggressive CS

      {0, 0, 0, 1, 0, 0}, // 10: light CPLX
      {0, 0, 0, 2, 0, 0}, // 11: moderate CPLX
      {0, 0, 0, 3, 0, 0}, // 12: aggressive CPLX

      {1, 1, 0, 0, 0, 0}, // 13: NL+GS
      {2, 2, 0, 0, 0, 0}, // 14: NL+GS stronger
      {1, 1, 1, 0, 0, 0}, // 15: NL+GS+CS light

      {2, 2, 2, 0, 0, 0}, // 16: NL+GS+CS medium
      {3, 2, 1, 0, 0, 0}, // 17: NL+GS+CS heavy

      {1, 0, 1, 1, 0, 0}, // 18: NL+CS+CPLX
      {2, 0, 2, 2, 0, 0}, // 19: NL+CS+CPLX med
      {0, 1, 1, 1, 0, 0}, // 20: GS+CS+CPLX

      {1, 1, 1, 1, 0, 0}, // 21: all light
      {2, 2, 2, 2, 0, 0}, // 22: all moderate
      {3, 3, 3, 3, 0, 0}, // 23: all aggressive

      {1, 2, 1, 0, 0, 0}, // 24: GS heavier
      {2, 1, 2, 1, 0, 0}, // 25: CPLX lighter

      {0, 2, 2, 1, 0, 0}, // 26: CS+GS+CPLX

      {2, 1, 1, 2, 0, 0}, // 27: NL+CPLX med

      {0, 0, 2, 2, 0, 0}, // 28: CS+CPLX only
      {1, 0, 1, 2, 0, 0}, // 29: NL+CS+CPLX

      {0, 2, 0, 2, 0, 0}, // 30: GS+CPLX only
      {3, 0, 3, 0, 0, 0}  // 31: NL+CS high
  };

  PrefetchAction a;
  a.action_nl = action_table[action_id][0];
  a.action_gs = action_table[action_id][1];
  a.action_cs = action_table[action_id][2];
  a.action_cplx = action_table[action_id][3];
  a.action_seq = action_table[action_id][4];
  a.action_rctp = action_table[action_id][5];
  return a;
}

void apply_confidence_boost()
{
  // Boost degree by +1 if confidence is good (>= 2)
  if (conf_nl >= 2 && class_control_nl.enabled)
    class_control_nl.prefetch_degree = std::min(class_control_nl.prefetch_degree + 1, 3);

  if (conf_gs >= 2 && class_control_gs.enabled)
    class_control_gs.prefetch_degree = std::min(class_control_gs.prefetch_degree + 1, 3);

  if (conf_cs >= 2 && class_control_cs.enabled)
    class_control_cs.prefetch_degree = std::min(class_control_cs.prefetch_degree + 1, 3);

  if (conf_cplx >= 2 && class_control_cplx.enabled)
    class_control_cplx.prefetch_degree = std::min(class_control_cplx.prefetch_degree + 1, 3);

  if (conf_seq >= 2 && class_control_seq.enabled)
    class_control_seq.prefetch_degree = std::min(class_control_seq.prefetch_degree + 1, 3);

  if (conf_rctp >= 2 && class_control_rctp.enabled)
    class_control_rctp.prefetch_degree = std::min(class_control_rctp.prefetch_degree + 1, 3);

  // Disable class if confidence is very bad (<= -3)
  if (conf_nl <= -3)
    class_control_nl.enabled = false;

  if (conf_gs <= -3)
    class_control_gs.enabled = false;

  if (conf_cs <= -3)
    class_control_cs.enabled = false;

  if (conf_cplx <= -3)
    class_control_cplx.enabled = false;

  if (conf_seq <= -3)
    class_control_seq.enabled = false;

  if (conf_rctp <= -3)
    class_control_rctp.enabled = false;
}

class IP_TABLE_L1
{
public:
  uint64_t ip_tag;
  uint64_t last_vpage;       // last page seen by IP
  uint64_t last_line_offset; // last cl offset in the 4KB page
  int64_t last_stride;       // last stride observed
  uint16_t ip_valid;         // valid bit
  int conf;                  // CS confidence
  uint16_t signature;        // CPLX signature
  uint16_t str_dir;          // stream direction
  uint16_t str_valid;        // stream valid
  uint16_t pref_type;        // pref type or class for book-keeping purposes.

  IP_TABLE_L1()
  {
    ip_tag = 0;
    last_vpage = 0;
    last_line_offset = 0;
    last_stride = 0;
    ip_valid = 0;
    signature = 0;
    conf = 0;
    str_dir = 0;
    str_valid = 0;
    pref_type = 0;
  };
};

/*	IP TABLE STORAGE OVERHEAD: 288 Bytes

        Single Entry:

        FIELD					STORAGE (bits)

        IP tag					9
        last page				2
        last line offset			6
        last stride				7 	(6 bits stride + 1 sign bit)
        IP valid				1
        confidence				2
        signature				7
        stream direction			1	1
        stream valid				1

        Total 					36

        Full Table Storage Overhead:

        64 entries * 36 bits = 2304 bits = 288 Bytes

        NOTE: The field prefetch class is used for book-keeping purposes.

*/

class CONST_STRIDE_PRED_TABLE
{
public:
  int stride;
  int conf;

  CONST_STRIDE_PRED_TABLE()
  {
    stride = 0;
    conf = 0;
  };
};

/*	CONSTANT STRIDE STORAGE OVERHEAD: 144 Bytes

        Single Entry:

        FIELD					STORAGE (bits)

        stride					7	(6 bits stride + 1 sign bit)
        confidence 				2

        Total					9

        Full Table Storage Overhead:

        128 entries * 9 bits = 1152 bits = 144 Bytes

*/

/* This class is for bookkeeping purposes only. */
class STAT_COLLECT
{
public:
  uint64_t useful;
  uint64_t filled;
  uint64_t misses;
  uint64_t polluted_misses;

  uint8_t bl_filled[NUM_BLOOM_ENTRIES];
  uint8_t bl_request[NUM_BLOOM_ENTRIES];

  STAT_COLLECT()
  {
    useful = 0;
    filled = 0;
    misses = 0;
    polluted_misses = 0;

    for (int i = 0; i < NUM_BLOOM_ENTRIES; i++) {
      bl_filled[i] = 0;
      bl_request[i] = 0;
    }
  };
};

class REGION_STREAM_TABLE
{
public:
  uint64_t region_id;
  uint64_t tentative_dense;                    // tentative dense bit
  uint64_t trained_dense;                      // trained dense bit
  uint64_t pos_neg_count;                      // positive/negative stream counter
  uint64_t dir;                                // direction of stream - 1 for +ve and 0 for -ve
  uint64_t lru;                                // lru for replacement
  uint8_t line_access[NUM_OF_LINES_IN_REGION]; // bit vector to store which lines in the 2KB region have been accessed
  REGION_STREAM_TABLE()
  {
    region_id = 0;
    tentative_dense = 0;
    trained_dense = 0;
    pos_neg_count = MAX_POS_NEG_COUNT / 2;
    dir = 0;
    lru = 0;
    for (int i = 0; i < NUM_OF_LINES_IN_REGION; i++)
      line_access[i] = 0;
  };
};

/*	REGION STREAM TABLE STORAGE OVERHEAD:

        Single Entry:

        FIELD					STORAGE (bits)

        region id				3
        tentative dense				1
        trained dense				1
        positive/negative count			6
        direction				1
        lru 					3
        bit vector line access			32	(for 2KB region)

        Total					47

        Full Table Storage Overhead:

        8 entries * 47 bits = 376 bits = 47 Bytes

*/

uint64_t ip_table_write_accesses = 0, ip_table_read_accesses = 0, rstable_write_accesses = 0, rstable_read_accesses = 0, cspt_write_accesses = 0,
         cspt_read_accesses = 0, rrfilter_read_accesses = 0, rrfilter_write_accesses = 0;
uint64_t ip_table_tag_write_accesses = 0, ip_table_tag_read_accesses = 0, rstable_tag_write_accesses = 0, rstable_tag_read_accesses = 0,
         rrfilter_tag_write_accesses = 0, rrfilter_tag_read_accesses = 0;
uint8_t warmup_flag_l1 = 0;

REGION_STREAM_TABLE rstable[NUM_RST_ENTRIES];
int acc_filled[5];
int acc_useful[5];

int acc[5];
int num_conflicts = 0;
uint64_t degree_decremented_times = 0, degree_incremented_times = 0;
int test;

uint64_t eval_buffer[1024] = {};
STAT_COLLECT stats[5]; // for GS, CS, CPLX, NL and no class
IP_TABLE_L1 trackers_l1[NUM_IP_TABLE_L1_ENTRIES];
CONST_STRIDE_PRED_TABLE CSPT_l1[NUM_CSPT_ENTRIES];

std::vector<uint64_t> recent_request_filter; // to filter redundant prefetch requests

/* 	RECENT REQUEST FILTER STORAGE OVERHEAD: 48 Bytes

        FIELD					STORAGE (bits)

        Tag					12

        Total Storage Overhead:

        32 entries * 12 bits = 384 bits = 48 Bytes

*/

uint64_t prev_cpu_cycle;
uint64_t num_misses;
float mpki = {0};
int spec_nl = {0}, flag_nl = {0};
uint64_t num_access;

int meta_counter[4] = {0}; // for book-keeping
int total_count = {0};     // for book-keeping

/* update_sig_l1: 7 bit signature is updated by performing a left-shift of 1 bit on the old signature and xoring the outcome with the delta*/

uint16_t update_sig_l1(uint16_t old_sig, int delta)
{
  uint16_t new_sig = 0;
  int sig_delta = 0;

  // 7-bit sign magnitude form, since we need to track deltas from +63 to -63
  sig_delta = (delta < 0) ? (((-1) * delta) + (1 << 6)) : delta;
  new_sig = ((old_sig << 1) ^ sig_delta) & ((1 << NUM_SIG_BITS) - 1);

  return new_sig;
}

/* encode_metadata: The stride, prefetch class type and speculative nl fields are encoded in the metadata. */

uint32_t encode_metadata(int stride, uint16_t type, int spec_nl)
{
  uint32_t metadata = 0;

  // first encode stride in the last 8 bits of the metadata
  if (stride > 0)
    metadata = stride;
  else
    metadata = ((-1 * stride) | 0b1000000);

  // encode the type of IP in the next 4 bits
  metadata = metadata | (type << 8);

  // encode the speculative NL bit in the next 1 bit
  metadata = metadata | (spec_nl << 12);

  return metadata;
}

/*If the actual stride and predicted stride are equal, then the confidence counter is incremented. */

int update_conf(int stride, int pred_stride, int conf)
{
#define MAX_CONF 3
  if (stride == pred_stride) { // use 2-bit saturating counter for confidence
    conf++;
    if (conf > MAX_CONF)
      conf = 3;
  } else {
    conf--;
    if (conf < 0)
      conf = 0;
  }

  return conf;
}

uint64_t hash_bloom(uint64_t addr)
{
  uint64_t first_half, sec_half;
  first_half = addr & 0xFFF;
  sec_half = (addr >> 12) & 0xFFF;
  if ((first_half ^ sec_half) >= 4096)
    assert(0);
  return ((first_half ^ sec_half) & 0xFFF);
}

uint64_t hash_page(uint64_t addr)
{
  uint64_t hash;
  while (addr != 0) {
    hash = hash ^ addr;
    addr = addr >> 6;
  }

  return hash & ((1 << NUM_PAGE_TAG_BITS) - 1);
}

void stat_col_L1(uint64_t addr, uint8_t cache_hit, uint64_t ip)
{
  uint64_t index = hash_bloom(addr);
  int ip_index = ip & ((1 << NUM_IP_INDEX_BITS) - 1);
  uint16_t ip_tag = (ip >> NUM_IP_INDEX_BITS) & ((1 << NUM_IP_TAG_BITS) - 1);

  for (int i = 0; i < 5; i++) {
    if (cache_hit) {
      if (stats[i].bl_filled[index] == 1) {
        stats[i].useful++;
        stats[i].filled++;
        stats[i].bl_filled[index] = 0;
      }
    } else {
      if (ip_tag == trackers_l1[ip_index].ip_tag) {
        if (trackers_l1[ip_index].pref_type == i)
          stats[i].misses++;
        if (stats[i].bl_filled[index] == 1) {
          stats[i].polluted_misses++;
          stats[i].filled++;
          stats[i].bl_filled[index] = 0;
        }
      }
    }

    if (num_misses % 1024 == 0) {
      for (int j = 0; j < NUM_BLOOM_ENTRIES; j++) {
        stats[i].filled += stats[i].bl_filled[j];
        stats[i].bl_filled[j] = 0;
        stats[i].bl_request[j] = 0;
      }
    }
  }
}

void ipcp::prefetcher_initialize()
{
  using namespace std;
  // Neelu: Adding a sanity check for number of sets to be a power of 2.
  int temp_num_sets = 1;
  for (int i = 1; i <= NUM_IP_INDEX_BITS; i++)
    temp_num_sets *= 2;

  if (temp_num_sets != NUM_IP_TABLE_L1_ENTRIES) {
    cout << "ERROR: --> num_sets: " << NUM_IP_TABLE_L1_ENTRIES << ", index_len: " << NUM_IP_INDEX_BITS << endl;
    cout << "ERROR: --> Oops: Num of sets are not 2^index_len. Kindly input cache sets and ways accordingly. <--" << endl;
    assert(0);
  }

  cout << "IP Table Entries: " << NUM_IP_TABLE_L1_ENTRIES << endl;
  cout << "CSPT Entries: " << NUM_CSPT_ENTRIES << endl;
  cout << "RR_ENTRIES: " << NUM_OF_RR_ENTRIES << endl;
  cout << "RST_ENTRIES: " << NUM_RST_ENTRIES << endl;

  for (int i = 0; i < NUM_RST_ENTRIES; i++)
    rstable[i].lru = i;
}

void ipcp::prefetcher_branch_operate(champsim::address ip, uint8_t branch_type, champsim::address branch_target)
{
  std::cout << "[BRANCH OPERATE]Cache :" << this->intern_->sim_stats.name << "     IP :" << ip.to<uint64_t>() << "    branch type :" << branch_type
            << "    branch target :" << branch_target << std::endl;
}

uint32_t ipcp::prefetcher_cache_operate(champsim::address addr, champsim::address ip, uint8_t cache_hit, bool useful_prefetch, access_type type,
                                        uint32_t metadata_in)
{
  // if(cache_hit && useful_prefetch){
  //   std::cout<< this->intern_->num_retired << std::endl;
  // }

  int prefetch_degree = 0;

  uint64_t set = this->intern_->get_set(addr.to<uint64_t>());
  uint64_t way = this->intern_->get_way(addr.to<uint64_t>(), set);
  champsim::cache_block cache_block = this->intern_->block[set * way];

  if (useful_prefetch && cache_block.pf_metadata != 0) {
    // std::cout << "[OPERATE]Cache :" << this->intern_->sim_stats.name << "     Address :" << addr << "    Metadata :" << cache_block.pf_metadata
    //           << "    Cache hit :" << (bool)cache_hit << "    Hits/Misses:" << this->intern_->sim_stats.pf_useful / this->intern_->sim_stats.pf_useless
    //           << std::endl;

    std::cout << "[OPERATE]Cache :" << this->intern_->sim_stats.name << "     Address :" << addr
              << "    Metadata :" << ((cache_block.pf_metadata & PREF_CLASS_MASK) >> NUM_OF_STRIDE_BITS)
              << "    Occupancy ratio :" << this->intern_->get_pq_occupancy_ratio()[2]
              << "    Metadata Expected:" << ((metadata_in & PREF_CLASS_MASK) >> NUM_OF_STRIDE_BITS) << std::endl;

    switch ((cache_block.pf_metadata & PREF_CLASS_MASK) >> NUM_OF_STRIDE_BITS) {
    case IPCP_CLASSES::NL:
      pf_nl_useful++;
      break;
    case IPCP_CLASSES::GS:
      pf_gs_useful++;
      break;
    case IPCP_CLASSES::CS:
      pf_cs_useful++;
      break;
    case IPCP_CLASSES::CPLX:
      pf_cplx_useful++;
      break;
    case IPCP_CLASSES::SEQ:
      pf_seq_useful++;
      break;
    case IPCP_CLASSES::RCTP:
      pf_rctp_useful++;
      break;
    default:
      break;
    }
  } else if (!useful_prefetch && (cache_block.pf_metadata != 0)) {

    switch ((cache_block.pf_metadata & PREF_CLASS_MASK) >> NUM_OF_STRIDE_BITS) {
    case IPCP_CLASSES::NL:
      pf_nl_not_useful++;
      break;
    case IPCP_CLASSES::GS:
      pf_gs_not_useful++;
      break;
    case IPCP_CLASSES::CS:
      pf_cs_not_useful++;
      break;
    case IPCP_CLASSES::CPLX:
      pf_cplx_not_useful++;
      break;
    case IPCP_CLASSES::SEQ:
      pf_seq_not_useful++;
      break;
    case IPCP_CLASSES::RCTP:
      pf_rctp_not_useful++;
      break;
    default:
      break;
    }
  }

  if (this->intern_->current_cycle() < 50000000) {
    ql_controller.epsilon = 1.0f; // Full random exploration
  } else {
    ql_controller.epsilon = 0.3f;
  }

  uint64_t mshr_ratio = this->intern_->get_mshr_occupancy_ratio();
  uint64_t pfq_ratio = this->intern_->get_pq_occupancy_ratio()[2];
  int total_useful = pf_nl_useful + pf_gs_useful + pf_cs_useful + pf_cplx_useful + pf_seq_useful + pf_rctp_useful;
  int total_not_useful = pf_nl_not_useful + pf_gs_not_useful + pf_cs_not_useful + pf_cplx_not_useful + pf_seq_not_useful + pf_rctp_not_useful;
  int total_prefetches = total_useful + total_not_useful;

  float usefulness_ratio = 0.0f;
  if (total_prefetches > 0) {
    usefulness_ratio = static_cast<float>(total_useful) / total_prefetches;
  }
  uint64_t current_core_cycle = this->intern_->current_cycle();
  if (current_core_cycle - last_decision_cycle > decision_interval) {
    // Step 1: Quantize current system state
    int mshr_bin = ql_controller.quantize_mshr(mshr_ratio);
    int pfq_bin = ql_controller.quantize_pfq(pfq_ratio);
    int cs_bin = ql_controller.quantize_usefulness_cs();
    int gs_bin = ql_controller.quantize_usefulness_gs();
    int nl_bin = ql_controller.quantize_usefulness_nl();
    int cplx_bin = ql_controller.quantize_usefulness_cplx();

    int current_state = ql_controller.get_state_index(mshr_bin, pfq_bin, cs_bin, gs_bin, nl_bin, cplx_bin);

    // Step 2: Select action
    int action_id = ql_controller.select_action(current_state);

    // Step 3: Decode action into per-class control
    PrefetchAction prefetch_action = decode_action(action_id);

    class_control_nl.prefetch_degree = prefetch_action.action_nl;
    class_control_nl.enabled = (prefetch_action.action_nl != 0);

    class_control_gs.prefetch_degree = prefetch_action.action_gs;
    class_control_gs.enabled = (prefetch_action.action_gs != 0);

    class_control_cs.prefetch_degree = prefetch_action.action_cs;
    class_control_cs.enabled = (prefetch_action.action_cs != 0);

    class_control_cplx.prefetch_degree = prefetch_action.action_cplx;
    class_control_cplx.enabled = (prefetch_action.action_cplx != 0);

    class_control_seq.prefetch_degree = prefetch_action.action_seq;
    class_control_seq.enabled = (prefetch_action.action_seq != 0);

    class_control_rctp.prefetch_degree = prefetch_action.action_rctp;
    class_control_rctp.enabled = (prefetch_action.action_rctp != 0);

    // class_control_rctp.prefetch_degree = 0;
    // class_control_rctp.enabled = false;

    // class_control_seq.prefetch_degree = 0;
    // class_control_seq.enabled = false;

    // Boost or disable based on class confidence
    // apply_confidence_boost();
    // Step 4: Calculate reward
    float reward = ql_controller.calculate_reward(total_useful, total_not_useful);

    // Step 5: Update Q-table
    ql_controller.update_q_table(last_state, last_action, reward, current_state);

    // Step 6: Update state tracking
    last_state = current_state;
    last_action = action_id;
    // update_class_confidences();

    // // Step 7: Reset counters
    pf_nl_useful = pf_nl_not_useful = 0;
    pf_gs_useful = pf_gs_not_useful = 0;
    pf_cs_useful = pf_cs_not_useful = 0;
    pf_cplx_useful = pf_cplx_not_useful = 0;
    pf_seq_useful = pf_seq_not_useful = 0;
    pf_rctp_useful = pf_rctp_not_useful = 0;

    last_decision_cycle = current_core_cycle;
  }

  if (warmup_flag_l1 == 0 && !this->intern_->warmup) {
    ip_table_write_accesses = 0;
    ip_table_read_accesses = 0;
    rstable_write_accesses = 0;
    rstable_read_accesses = 0;
    cspt_write_accesses = 0;
    cspt_read_accesses = 0;
    rrfilter_write_accesses = 0;
    rrfilter_read_accesses = 0;
    ip_table_tag_write_accesses = 0;
    ip_table_tag_read_accesses = 0;
    rstable_tag_write_accesses = 0;
    rstable_tag_read_accesses = 0;
    // cspt_tag_write_accesses = 0;
    // cspt_tag_read_accesses = 0;
    rrfilter_tag_write_accesses = 0;
    rrfilter_tag_read_accesses = 0;
    num_conflicts = 0;
    warmup_flag_l1 = 1;
  }

#ifdef CRITICAL_IP_PREF
  if (critical_ip_flag == 0)
    return;
#endif

  uint64_t curr_page = hash_page(addr.to<uint64_t>() >> LOG2_PAGE_SIZE);  // current page
  uint64_t line_addr = addr.to<uint64_t>() >> LOG2_BLOCK_SIZE;            // cache line address
  uint64_t line_offset = (addr.to<uint64_t>() >> LOG2_BLOCK_SIZE) & 0x3F; // cache line offset
  uint16_t signature = 0, last_signature = 0;
  int spec_nl_threshold = 0;
  int num_prefs = 0;
  uint32_t metadata = 0;
  uint16_t ip_tag = (ip.to<uint64_t>() >> NUM_IP_INDEX_BITS) & ((1 << NUM_IP_TAG_BITS) - 1);
  uint64_t bl_index = 0;

  if (NUM_CPUS == 1) {
    spec_nl_threshold = 50;
  } else { // tightening the mpki constraints for multi-core
    spec_nl_threshold = 40;
  }

  // update miss counter
  if (cache_hit == 0 && !this->intern_->warmup)
    num_misses += 1;
  num_access += 1;
  stat_col_L1(addr.to<uint64_t>(), cache_hit, ip.to<uint64_t>());
  // update spec nl bit when num misses crosses certain threshold

  if (num_misses % 256 == 0 && cache_hit == 0) {

    mpki = ((num_misses * 1000.0) / (this->intern_->num_retired - 50000000));

    if (mpki > spec_nl_threshold)
      spec_nl = 0;
    else
      spec_nl = 1;
  }

  // Updating prefetch degree based on accuracy
  // for (int i = 0; i < 5; i++) {
  //   if (this->intern_->pref_filled[i] % 256 == 0) {

  //     acc_useful[i] = acc_useful[i] / 2.0 + (this->intern_->pref_useful[i] - acc_useful[i]) / 2.0;
  //     acc_filled[i] = acc_filled[i] / 2.0 + (this->intern_->pref_filled[i] - acc_filled[i]) / 2.0;

  //     if (acc_filled[i] != 0)
  //       acc[i] = 100.0 * acc_useful[i] / (acc_filled[i]);
  //     else
  //       acc[i] = 60;

  //     if (acc[i] > 75) {
  //       degree_incremented_times++;
  //       prefetch_degree[i]++;
  //       if (i == 1) {
  //         // For GS class, degree is incremented/decremented by 2.
  //         prefetch_degree[i]++;
  //         if (prefetch_degree[i] > 6)
  //           prefetch_degree[i] = 6;
  //       } else if (prefetch_degree[i] > 3)
  //         prefetch_degree[i] = 3;
  //     } else if (acc[i] < 40) {
  //       degree_decremented_times++;
  //       prefetch_degree[i]--;
  //       if (i == 1)
  //         prefetch_degree[i]--;
  //       if (prefetch_degree[i] < 1)
  //         prefetch_degree[i] = 1;
  //     }
  //   }
  // }

  // increment one access for tag read, it will be one+ for tag write too I guess?
  ip_table_tag_read_accesses++;
  ip_table_tag_write_accesses++;

  // calculate the index bit
  int index = ip.to<uint64_t>() & ((1 << NUM_IP_INDEX_BITS) - 1);
  if (trackers_l1[index].ip_tag != ip_tag) { // new/conflict IP
    if (trackers_l1[index].ip_valid == 0) {  // if valid bit is zero, update with latest IP info
      num_conflicts++;

      // increment one write access.
      ip_table_write_accesses++;

      trackers_l1[index].ip_tag = ip_tag;
      trackers_l1[index].last_vpage = curr_page;
      trackers_l1[index].last_line_offset = line_offset;
      trackers_l1[index].last_stride = 0;
      trackers_l1[index].signature = 0;
      trackers_l1[index].conf = 0;
      trackers_l1[index].str_valid = 0;
      trackers_l1[index].str_dir = 0;
      trackers_l1[index].pref_type = 0;
      trackers_l1[index].ip_valid = 1;
    } else { // otherwise, reset valid bit and leave the previous IP as it is
      trackers_l1[index].ip_valid = 0;
    }

    return metadata;
  } else { // if same IP encountered, set valid bit
    trackers_l1[index].ip_valid = 1;
  }

  // Incrementing read and write access for IP table.
  ip_table_write_accesses++;
  ip_table_read_accesses++;

  // calculate the stride between the current cache line offset and the last cache line offset
  int64_t stride = 0;
  if (line_offset > trackers_l1[index].last_line_offset)
    stride = line_offset - trackers_l1[index].last_line_offset;
  else {
    stride = trackers_l1[index].last_line_offset - line_offset;
    stride *= -1;
  }

  // don't do anything if same address is seen twice in a row
  if (stride == 0)
    return metadata;

  int c = 0, flag = 0;

  // incrementing one read access for rs_table
  // rstable_read_accesses++;

  // Checking if IP is already classified as a part of the GS class, so that for the new region we will set the tentative (spec_dense) bit.
  for (int i = 0; i < NUM_RST_ENTRIES; i++) {
    rstable_tag_read_accesses++;
    if (rstable[i].region_id == ((trackers_l1[index].last_vpage << 1) | (trackers_l1[index].last_line_offset >> 5))) {
      rstable_read_accesses++;
      if (rstable[i].trained_dense == 1)
        flag = 1;
      break;
    }
  }
  for (c = 0; c < NUM_RST_ENTRIES; c++) {
    rstable_tag_read_accesses++;
    if (((curr_page << 1) | (line_offset >> 5)) == rstable[c].region_id) {
      rstable_read_accesses++;
      rstable_write_accesses++;
      if (rstable[c].line_access[line_offset & REGION_OFFSET_MASK] == 0) {
        rstable[c].line_access[line_offset & REGION_OFFSET_MASK] = 1;
      }

      if (rstable[c].pos_neg_count >= MAX_POS_NEG_COUNT || rstable[c].pos_neg_count <= 0) {
        rstable[c].pos_neg_count = MAX_POS_NEG_COUNT / 2;
      }

      if (stride > 0)
        rstable[c].pos_neg_count++;
      else
        rstable[c].pos_neg_count--;

      if (rstable[c].trained_dense == 0) {
        int count = 0;
        for (int i = 0; i < NUM_OF_LINES_IN_REGION; i++)
          if (rstable[c].line_access[line_offset & REGION_OFFSET_MASK] == 1)
            count++;

        if (count > 24) // 75% of the cache lines in the region are accessed.
        {
          rstable[c].trained_dense = 1;
        }
      }
      if (flag == 1)
        rstable[c].tentative_dense = 1;
      if (rstable[c].tentative_dense == 1 || rstable[c].trained_dense == 1) {
        if (rstable[c].pos_neg_count > (MAX_POS_NEG_COUNT / 2))
          rstable[c].dir = 1; // 1 for positive direction
        else
          rstable[c].dir = 0; // 0 for negative direction
        trackers_l1[index].str_valid = 1;

        trackers_l1[index].str_dir = rstable[c].dir;
      } else
        trackers_l1[index].str_valid = 0;

      // I tested updating the lru with mcf-782, it did not make a difference in IPC. I guess it has to do with less number of regions? Not sure.
      /*for (int i=0; i<NUM_RST_ENTRIES; i++) {
              //incrementing one read access for rs_table
              //rstable_read_accesses++;
              if (rstable[i].lru < rstable[c].lru)
              {
                  rstable[i].lru++;
                  //incrementing one write access for rs_table
                  rstable_tag_write_accesses++;
              }
      }
      rstable_tag_write_accesses++;
      rstable[c].lru = 0; */

      break;
    }
  }
  // curr page has no entry in rstable. Then replace lru.
  if (c == NUM_RST_ENTRIES) {
    // check lru
    for (c = 0; c < NUM_RST_ENTRIES; c++) {
      // incrementing one read access for rs_table
      rstable_tag_read_accesses++;
      if (rstable[c].lru == (NUM_RST_ENTRIES - 1))
        break;
    }
    for (int i = 0; i < NUM_RST_ENTRIES; i++) {
      // incrementing one read access for rs_table
      // rstable_read_accesses++;
      if (rstable[i].lru < rstable[c].lru) {
        rstable[i].lru++;
        // incrementing one write access for rs_table
        rstable_tag_write_accesses++;
      }
    }
    if (flag == 1)
      rstable[c].tentative_dense = 1;
    else
      rstable[c].tentative_dense = 0;

    rstable[c].region_id = (curr_page << 1) | (line_offset >> 5);
    rstable[c].trained_dense = 0;
    rstable[c].pos_neg_count = MAX_POS_NEG_COUNT / 2;
    rstable[c].dir = 0;
    rstable[c].lru = 0;
    for (int i = 0; i < NUM_OF_LINES_IN_REGION; i++)
      rstable[c].line_access[i] = 0;

    // incrementing one write access for rs_table
    rstable_write_accesses++;
    rstable_tag_write_accesses++;
  }

  // page boundary learning
  if (curr_page != trackers_l1[index].last_vpage) {
    test++;
    if (stride < 0)
      stride += NUM_OF_LINES_IN_REGION;
    else
      stride -= NUM_OF_LINES_IN_REGION;
  }

  if (stride != 0) {
    sequitur_predictor.feed_delta(stride);
  }

  // Train Region Table
  uint64_t region_tag = addr.to<uint64_t>() >> 12;                          // 4KB region
  uint64_t offset_in_region = addr.to<uint64_t>() & (RCTP_REGION_SIZE - 1); // Offset inside region (0-4095)

  if (!region_table.count(region_tag)) {
    region_table[region_tag] = RegionEntry{region_tag, {}, {}, this->intern_->current_cycle()};
  }

  offset_in_region = addr.to<uint64_t>() & (RCTP_REGION_SIZE - 1); // mask lower 12 bits

  // Save the stride seen at this region
  region_table[region_tag].deltas.push_back(stride);
  region_table[region_tag].offsets.push_back(offset_in_region);
  if (region_table[region_tag].deltas.size() > 4) {
    region_table[region_tag].deltas.erase(region_table[region_tag].deltas.begin());
  }
  if (region_table[region_tag].offsets.size() > 16) {
    region_table[region_tag].offsets.erase(region_table[region_tag].offsets.begin());
  }

  // Train distance accuracy
  // Assume if two consecutive accesses were from regions X and Y
  // then the distance = (Y region tag - X region tag)
  static uint64_t last_region_tag = 0;
  static bool first_region_access = true;

  if (!first_region_access) {
    int64_t region_distance = static_cast<int64_t>(region_tag) - static_cast<int64_t>(last_region_tag);
    distance_accuracy_table[region_distance]++;
  }
  first_region_access = false;
  last_region_tag = region_tag;

  // update constant stride(CS) confidence
  trackers_l1[index].conf = update_conf(stride, trackers_l1[index].last_stride, trackers_l1[index].conf);

  // update CS only if confidence is zero
  if (trackers_l1[index].conf == 0)
    trackers_l1[index].last_stride = stride;

  last_signature = trackers_l1[index].signature;
  // update complex stride(CPLX) confidence
  CSPT_l1[last_signature].conf = update_conf(stride, CSPT_l1[last_signature].stride, CSPT_l1[last_signature].conf);

  // incrementing one write access for cspt (includes stride updation too from the code just below.)
  cspt_write_accesses++;
  cspt_read_accesses++; // one read access to read the last stride and confidence

  // update CPLX only if confidence is zero
  if (CSPT_l1[last_signature].conf == 0)
    CSPT_l1[last_signature].stride = stride;

  // calculate and update new signature in IP table
  signature = update_sig_l1(last_signature, stride);
  trackers_l1[index].signature = signature;

  SIG_DP(cout << ip << ", " << cache_hit << ", " << line_addr << ", " << addr << ", " << stride << "; ";
         cout << last_signature << ", " << CSPT_l1[last_signature].stride << ", " << CSPT_l1[last_signature].conf << "; ";
         cout << trackers_l1[index].last_stride << ", " << stride << ", " << trackers_l1[index].conf << ", " << "; ";);

  /**
   *
   * Global stream
   *
   */
  if (class_control_gs.enabled && trackers_l1[index].str_valid == 1) { // stream IP
    // for stream, prefetch with twice the usual degree

    prefetch_degree = class_control_gs.prefetch_degree;

    meta_counter[0]++;
    total_count++;
    for (int i = 0; i < prefetch_degree; i++) {
      uint64_t pf_address = 0;

      if (trackers_l1[index].str_dir == 1) { // +ve stream
        pf_address = (line_addr + i + 1) << LOG2_BLOCK_SIZE;
        metadata = encode_metadata(1, S_TYPE, spec_nl); // stride is 1
      } else {                                          // -ve stream
        pf_address = (line_addr - i - 1) << LOG2_BLOCK_SIZE;
        metadata = encode_metadata(-1, S_TYPE, spec_nl); // stride is -1
      }

      if (acc[1] < 75)
        metadata = encode_metadata(0, S_TYPE, spec_nl);
      // Check if prefetch address is in same 4 KB page
      if ((pf_address >> LOG2_PAGE_SIZE) != (addr.to<uint64_t>() >> LOG2_PAGE_SIZE)) {
        break;
      }

      trackers_l1[index].pref_type = S_TYPE;

#ifdef DO_PREF
      rrfilter_read_accesses++;
      int found_in_filter = 0;
      for (int i = 0; i < recent_request_filter.size(); i++) {
        rrfilter_tag_read_accesses++;
        if (recent_request_filter[i] == ((pf_address >> 6) & RR_TAG_MASK)) {
          // Prefetch address is present in RR filter
          found_in_filter = 1;
          break;
        }
      }
      // Issue prefetch request only if prefetch address is not present in RR filter
      if (found_in_filter == 0) {
        prefetch_line(pf_address, true, metadata);
        // Add to RR filter
        rrfilter_tag_write_accesses++;
        recent_request_filter.push_back((pf_address >> 6) & RR_TAG_MASK);
        if (recent_request_filter.size() > NUM_OF_RR_ENTRIES)
          recent_request_filter.erase(recent_request_filter.begin());
      }
#endif
      num_prefs++;
      SIG_DP(cout << "1, ");
    }
  }

  /**
   *
   * Constant stride
   *
   */
  if (class_control_cs.enabled && trackers_l1[index].conf > 1 && trackers_l1[index].last_stride != 0) { // CS IP
    meta_counter[1]++;
    total_count++;
    prefetch_degree = class_control_cs.prefetch_degree;

    for (int i = 0; i < prefetch_degree; i++) {
      uint64_t pf_address = (line_addr + (trackers_l1[index].last_stride * (i + 1))) << LOG2_BLOCK_SIZE;

      // Check if prefetch address is in same 4 KB page
      if ((pf_address >> LOG2_PAGE_SIZE) != (addr.to<uint64_t>() >> LOG2_PAGE_SIZE)) {
        break;
      }

      trackers_l1[index].pref_type = CS_TYPE;
      bl_index = hash_bloom(pf_address);
      stats[CS_TYPE].bl_request[bl_index] = 1;
      if (acc[2] > 75)
        metadata = encode_metadata(trackers_l1[index].last_stride, CS_TYPE, spec_nl);
      else
        metadata = encode_metadata(0, CS_TYPE, spec_nl);
// if(spec_nl == 1)
#ifdef DO_PREF
      rrfilter_read_accesses++;
      int found_in_filter = 0;
      for (int i = 0; i < recent_request_filter.size(); i++) {
        rrfilter_tag_read_accesses++;
        if (recent_request_filter[i] == ((pf_address >> 6) & RR_TAG_MASK)) {
          // Prefetch address is present in RR filter
          found_in_filter = 1;
          break;
        }
      }
      // Issue prefetch request only if prefetch address is not present in RR filter
      if (found_in_filter == 0) {
        prefetch_line(pf_address, true, metadata);
        // Add to RR filter
        rrfilter_tag_write_accesses++;
        recent_request_filter.push_back((pf_address >> 6) & RR_TAG_MASK);
        if (recent_request_filter.size() > NUM_OF_RR_ENTRIES)
          recent_request_filter.erase(recent_request_filter.begin());
      }
#endif
      num_prefs++;
      SIG_DP(cout << trackers_l1[index].last_stride << ", ");
    }
  }

  /**
   *
   * CPLX
   *
   */
  if (class_control_cplx.enabled && CSPT_l1[signature].conf >= 0 && CSPT_l1[signature].stride != 0) { // if conf>=0, continue looking for stride
    int pref_offset = 0, i = 0;                                                                       // CPLX IP
    meta_counter[2]++;
    total_count++;
    prefetch_degree = class_control_cplx.prefetch_degree;

    for (i = 0; i < prefetch_degree + CPLX_DIST; i++) {
      cspt_read_accesses++;
      pref_offset += CSPT_l1[signature].stride;
      uint64_t pf_address = ((line_addr + pref_offset) << LOG2_BLOCK_SIZE);

      // Check if prefetch address is in same 4 KB page
      if (((pf_address >> LOG2_PAGE_SIZE) != (addr.to<uint64_t>() >> LOG2_PAGE_SIZE)) || (CSPT_l1[signature].conf == -1) || (CSPT_l1[signature].stride == 0)) {
        // if new entry in CSPT or stride is zero, break
        break;
      }

      // we are not prefetching at L2 for CPLX type, so encode stride as 0
      trackers_l1[index].pref_type = CPLX_TYPE;
      metadata = encode_metadata(0, CPLX_TYPE, spec_nl);
#define MIN_CONF 0                                                // Default 0
      if (CSPT_l1[signature].conf > MIN_CONF && i >= CPLX_DIST) { // prefetch only when conf>0 for CPLX
        bl_index = hash_bloom(pf_address);
        stats[CPLX_TYPE].bl_request[bl_index] = 1;
        trackers_l1[index].pref_type = 3;
#ifdef DO_PREF
        rrfilter_read_accesses++;
        int found_in_filter = 0;
        for (int i = 0; i < recent_request_filter.size(); i++) {
          rrfilter_tag_read_accesses++;
          if (recent_request_filter[i] == ((pf_address >> 6) & RR_TAG_MASK)) {
            // Prefetch address is present in RR filter
            found_in_filter = 1;
            break;
          }
        }
        // Issue prefetch request only if prefetch address is not present in RR filter
        if (found_in_filter == 0) {
          prefetch_line(pf_address, true, metadata);
          // Add to RR filter
          rrfilter_tag_write_accesses++;
          recent_request_filter.push_back((pf_address >> 6) & RR_TAG_MASK);
          if (recent_request_filter.size() > NUM_OF_RR_ENTRIES)
            recent_request_filter.erase(recent_request_filter.begin());
        }
#endif
        num_prefs++;
        SIG_DP(cout << pref_offset << ", ");
      }
      signature = update_sig_l1(signature, CSPT_l1[signature].stride);
    }
  }

  /**
   *
   * Sequitur
   *
   */
  if (class_control_seq.enabled) { // Sequitur fallback before NL
    prefetch_degree = class_control_seq.prefetch_degree;

    std::vector<int64_t> preds = sequitur_predictor.predict_next();
    int issued = 0; // Track how many prefetches issued

    for (auto delta : preds) {
      if (issued >= prefetch_degree)
        break; // Limit by prefetch degree

      uint64_t pf_address = (line_addr + delta) << LOG2_BLOCK_SIZE;

      // Check if prefetch address stays in same 4KB page
      if ((pf_address >> LOG2_PAGE_SIZE) != (addr.to<uint64_t>() >> LOG2_PAGE_SIZE))
        break;

      pf_seq_lc++;
      if (prefetch_line(champsim::address{pf_address}, true, 5)) {
        pf_seq++;
        num_prefs++;
      }

      issued++; // Increment prefetch issued count
    }
  }

  /**
   *
   * RCTP
   *
   */
  if (class_control_rctp.enabled) { // RCTP enabled
    uint64_t region_tag = addr.to<uint64_t>() >> 12;
    uint64_t offset_in_region = addr.to<uint64_t>() & (RCTP_REGION_SIZE - 1);

    bool found_prediction = false;

    int max_rctp_prefetches = class_control_rctp.prefetch_degree; // 🛠 Apply degree control here

    for (auto& entry : region_table) {
      int64_t region_distance = static_cast<int64_t>(region_tag) - static_cast<int64_t>(entry.first);

      if (distance_accuracy_table[region_distance] > 2) {
        bool offset_matched = false;
        for (auto off : entry.second.offsets) {
          if (std::abs(static_cast<int64_t>(off) - static_cast<int64_t>(offset_in_region)) <= 8) {
            offset_matched = true;
            break;
          }
        }

        if (offset_matched) {
          int issued_rctp_pfs = 0;
          for (auto delta : entry.second.deltas) {
            if (issued_rctp_pfs >= max_rctp_prefetches) // 🛠 Stop when degree prefetched
              break;

            uint64_t pf_address = (line_addr + delta) << LOG2_BLOCK_SIZE;

            if ((pf_address >> LOG2_PAGE_SIZE) != (addr.to<uint64_t>() >> LOG2_PAGE_SIZE))
              break;

            if (prefetch_line(champsim::address{pf_address}, true, 6)) {
              num_prefs++;
              issued_rctp_pfs++;
            }
          }
          found_prediction = true;
        }
      }
      if (found_prediction)
        break;
    }
  }

  /**
   *
   * Next Line
   *
   */
  if (class_control_nl.enabled) {
    prefetch_degree = class_control_nl.prefetch_degree;
    if (flag_nl == 0)
      flag_nl = 1;
    else {
      uint64_t pf_address = ((addr.to<uint64_t>() >> LOG2_BLOCK_SIZE) + 1) << LOG2_BLOCK_SIZE;
      if ((pf_address >> LOG2_PAGE_SIZE) != (addr.to<uint64_t>() >> LOG2_PAGE_SIZE)) {
        // update the IP table entries
        trackers_l1[index].last_line_offset = line_offset;
        trackers_l1[index].last_vpage = curr_page;

        return metadata;
      }
      bl_index = hash_bloom(pf_address);
      stats[NL_TYPE].bl_request[bl_index] = 1;
      metadata = encode_metadata(1, NL_TYPE, spec_nl);
#ifdef DO_PREF
      rrfilter_read_accesses++;
      int found_in_filter = 0;
      for (int i = 0; i < recent_request_filter.size(); i++) {
        rrfilter_tag_read_accesses++;
        if (recent_request_filter[i] == ((pf_address >> 6) & RR_TAG_MASK)) {
          // Prefetch address is present in RR filter
          found_in_filter = 1;
          break;
        }
      }
      // Issue prefetch request only if prefetch address is not present in RR filter
      if (found_in_filter == 0) {
        prefetch_line(pf_address, true, metadata);
        // Add to RR filter
        rrfilter_tag_write_accesses++;
        recent_request_filter.push_back((pf_address >> 6) & RR_TAG_MASK);
        if (recent_request_filter.size() > NUM_OF_RR_ENTRIES)
          recent_request_filter.erase(recent_request_filter.begin());
      }
#endif
      trackers_l1[index].pref_type = NL_TYPE;
      meta_counter[3]++;
      total_count++;
      SIG_DP(cout << "1, ");

      if (acc[4] < 40)
        flag_nl = 0;
    } // NL IP
  }

  SIG_DP(cout << endl);

  // update the IP table entries
  trackers_l1[index].last_line_offset = line_offset;
  trackers_l1[index].last_vpage = curr_page;

  static uint64_t last_age_check = 0;
  const uint64_t AGE_CHECK_INTERVAL = 100000;  // every 100K instructions
  const uint64_t REGION_EXPIRY_CYCLES = 50000; // expire if not accessed for 50K cycles

  if (this->intern_->current_cycle() - last_age_check > AGE_CHECK_INTERVAL) {
    for (auto it = region_table.begin(); it != region_table.end();) {
      if (this->intern_->current_cycle() - it->second.last_access_cycle > REGION_EXPIRY_CYCLES) {
        it = region_table.erase(it); // Remove stale region
      } else {
        ++it;
      }
    }
    last_age_check = this->intern_->current_cycle();
  }

  return metadata;
}

uint32_t ipcp::prefetcher_cache_fill(champsim::address addr, long set, long way, uint8_t prefetch, champsim::address evicted_addr, uint32_t metadata_in)
{

  if (prefetch) {
    uint32_t pref_type = metadata_in & 0xF00;
    pref_type = pref_type >> 8;

    uint64_t index = hash_bloom(addr.to<uint64_t>());
    if (stats[pref_type].bl_request[index] == 1) {
      stats[pref_type].bl_filled[index] = 1;
      stats[pref_type].bl_request[index] = 0;
    }
  }

  if (prefetch) {
    // std::cout<< "[FILL]Cache :" << this->intern_->sim_stats.name << "     Address :" << addr << "    Metadata :" << (int)metadata_in << "    Evicted :" <<
    // evicted_addr << std::endl;

    switch ((metadata_in & PREF_CLASS_MASK) >> NUM_OF_STRIDE_BITS) {
    case IPCP_CLASSES::NL:
      pf_nl_fill++;
      break;
    case IPCP_CLASSES::GS:
      pf_gs_fill++;
      break;
    case IPCP_CLASSES::CS:
      pf_cs_fill++;
      break;
    case IPCP_CLASSES::CPLX:
      pf_cplx_fill++;
      break;
    case IPCP_CLASSES::SEQ:
      pf_seq_fill++;
      break;
    case IPCP_CLASSES::RCTP:
      pf_rctp_fill++;
      break;
    default:
      // pf_default_fill++;
      break;
    }
  }
  return metadata_in;
}
void ipcp::prefetcher_final_stats()
{
  using namespace std;
  cout << endl;

  uint64_t total_request = 0, total_polluted = 0, total_useful = 0, total_late = 0;

  for (int i = 0; i < 5; i++) {
    total_request += this->intern_->pref_filled[i];
    total_polluted += stats[i].polluted_misses;
    total_useful += this->intern_->pref_useful[i];
    total_late += this->intern_->pref_late[i];
  }

  cout << "stream: " << endl;
  cout << "stream:times selected: " << meta_counter[0] << endl;
  cout << "stream:pref_filled: " << this->intern_->pref_filled[1] << endl;
  cout << "stream:pref_useful: " << this->intern_->pref_useful[1] << endl;
  cout << "stream:pref_late: " << this->intern_->pref_late[1] << endl;
  cout << "stream:misses: " << stats[1].misses << endl;
  cout << "stream:misses_by_poll: " << stats[1].polluted_misses << endl;
  cout << endl;

  cout << "CS: " << endl;
  cout << "CS:times selected: " << meta_counter[1] << endl;
  cout << "CS:pref_filled: " << this->intern_->pref_filled[2] << endl;
  cout << "CS:pref_useful: " << this->intern_->pref_useful[2] << endl;
  cout << "CS:pref_late: " << this->intern_->pref_late[2] << endl;
  cout << "CS:misses: " << stats[2].misses << endl;
  cout << "CS:misses_by_poll: " << stats[2].polluted_misses << endl;
  cout << endl;

  cout << "CPLX: " << endl;
  cout << "CPLX:times selected: " << meta_counter[2] << endl;
  cout << "CPLX:pref_filled: " << this->intern_->pref_filled[3] << endl;
  cout << "CPLX:pref_useful: " << this->intern_->pref_useful[3] << endl;
  cout << "CPLX:pref_late: " << this->intern_->pref_late[3] << endl;
  cout << "CPLX:misses: " << stats[3].misses << endl;
  cout << "CPLX:misses_by_poll: " << stats[3].polluted_misses << endl;
  cout << endl;

  cout << "NL_L1: " << endl;
  cout << "NL:times selected: " << meta_counter[3] << endl;
  cout << "NL:pref_filled: " << this->intern_->pref_filled[4] << endl;
  cout << "NL:pref_useful: " << this->intern_->pref_useful[4] << endl;
  cout << "NL:pref_late: " << this->intern_->pref_late[4] << endl;
  cout << "NL:misses: " << stats[4].misses << endl;
  cout << "NL:misses_by_poll: " << stats[4].polluted_misses << endl;
  cout << endl;

  cout << "total selections: " << total_count << endl;
  cout << "pf_fill: " << this->intern_->sim_stats.pf_fill << endl;
  cout << "pf_useful: " << this->intern_->sim_stats.pf_useful << endl;
  // cout << "total_filled: " << total_f << endl;
  cout << "total_useful: " << total_useful << endl;
  cout << "total_late: " << total_late << endl;
  cout << "total_polluted: " << total_polluted << endl;
  cout << "total_misses_after_warmup: " << num_misses << endl;

  cout << "conflicts: " << num_conflicts << endl;

  cout << "Degree Incremented Times: " << degree_incremented_times << endl;
  cout << "Degree Decremented Times: " << degree_decremented_times << endl;

  cout << endl;

  cout << "L1 IP Table Write Accesses: " << ip_table_write_accesses << endl;
  cout << "L1 IP Table Read Accesses: " << ip_table_read_accesses << endl;
  cout << "L1 RST Write Accesses: " << rstable_write_accesses << endl;
  cout << "L1 RST Read Accesses: " << rstable_read_accesses << endl;
  cout << "L1 CSPT Write Accesses: " << cspt_write_accesses << endl;
  cout << "L1 CSPT Read Accesses: " << cspt_read_accesses << endl;
  cout << "L1 RR Filter Tag Write Accesses: " << rrfilter_tag_write_accesses << endl;
  cout << "L1 RR Filter Tag Read Accesses: " << rrfilter_tag_read_accesses << endl;
  cout << "L1 IP Table Tag Write Accesses: " << ip_table_tag_write_accesses << endl;
  cout << "L1 IP Table Tag Read Accesses: " << ip_table_tag_read_accesses << endl;
  cout << "L1 RST Tag Write Accesses: " << rstable_tag_write_accesses << endl;
  cout << "L1 RST Tag Read Accesses: " << rstable_tag_read_accesses << endl;
  cout << "L1 RR Filter Write Accesses: " << rrfilter_write_accesses << endl;
  cout << "L1 RR Filter Read Accesses: " << rrfilter_read_accesses << endl;

  cout << "*** Final Statistics ***" << endl;

  // cout << "PF NL LC :" << pf_nl_lc << endl;
  // cout << "PF GS LC :" << pf_gs_lc << endl;
  // cout << "PF CS LC :" << pf_cs_lc << endl;
  // cout << "PF CPLX LC :" << pf_cplx_lc << endl;
  cout << "*** PF Requested ***" << endl;

  cout << "NL :" << pf_nl << endl;
  cout << "GS :" << pf_gs << endl;
  cout << "CS :" << pf_cs << endl;
  cout << "CPLX :" << pf_cplx << endl;
  cout << "SEQ :" << pf_seq << endl;
  cout << "RCTP :" << pf_rctp << endl;

  cout << "*** PF Filled ***" << endl;

  cout << "NL :" << pf_nl_fill << endl;
  cout << "GS :" << pf_gs_fill << endl;
  cout << "CS :" << pf_cs_fill << endl;
  cout << "CPLX :" << pf_cplx_fill << endl;
  cout << "SEQ :" << pf_cplx_fill << endl;
  cout << "RCTP :" << pf_rctp_fill << endl;

  cout << "*** Useful ***" << endl;
  cout << "NL:" << pf_nl_useful << endl;
  cout << "GS :" << pf_gs_useful << endl;
  cout << "CS :" << pf_cs_useful << endl;
  cout << "CPLX :" << pf_cplx_useful << endl;
  cout << "SEQ :" << pf_seq_useful << endl;
  cout << "RCTP :" << pf_rctp_useful << endl;

  cout << "*** Not Useful ***" << endl;
  cout << "NL:" << pf_nl_not_useful << endl;
  cout << "GS :" << pf_gs_not_useful << endl;
  cout << "CS :" << pf_cs_not_useful << endl;
  cout << "CPLX :" << pf_cplx_not_useful << endl;
  cout << "SEQ :" << pf_seq_not_useful << endl;
  cout << "RCTP :" << pf_rctp_not_useful << endl;

  // cout << "*** Usefulness percentage ***" << endl;
  // cout << "NL:" << pf_nl_useful / pf_nl_not_useful << endl;
  // cout << "GS :" << pf_gs_useful / pf_gs_not_useful << endl;
  // cout << "CS :" << pf_cs_useful / pf_cs_not_useful << endl;
  // cout << "CPLX :" << pf_cplx_useful / pf_cplx_not_useful << endl;
  // cout << "SEQ :" << pf_seq_useful / pf_seq_not_useful << endl;
  // cout << "RCTP :" << pf_rctp_useful / pf_rctp_not_useful << endl;

  cout << "*************************" << endl;
}
