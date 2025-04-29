#include "ipcp.h"

#include <access_type.h>
#include <iostream>
#include <vector>

#include "cache.h"

#define NUM_IP_TABLE_L1_ENTRIES 1024 // IP table entries
#define NUM_GHB_ENTRIES 16           // Entries in the GHB
#define NUM_IP_INDEX_BITS 10         // Bits to index into the IP table
#define NUM_IP_TAG_BITS 6            // Tag bits per IP table entry
#define S_TYPE 1                     // stream
#define CS_TYPE 2                    // constant stride
#define CPLX_TYPE 3                  // complex stride
#define NL_TYPE 4                    // next line

// #define DEBUG_PRINT
#ifdef SIG_DEBUG_PRINT
#define SIG_DP(x) x
#else
#define SIG_DP(x)
#endif
      // NL, GS, CS, CPLX, SEQ, RCTP

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

/*
 * IP Table
 *
 * */

class IP_TABLE_L1
{
public:
  uint64_t ip_tag;
  uint64_t last_page;      // last page seen by IP
  uint64_t last_cl_offset; // last cl offset in the 4KB page
  int64_t last_stride;     // last delta observed
  // int64_t last_stride2;
  uint16_t ip_valid;     // Valid IP or not
  int conf;              // CS conf
  uint16_t signature;    // CPLX signature
  uint16_t str_dir;      // stream direction
  uint16_t str_valid;    // stream valid
  uint16_t str_strength; // stream strength

  IP_TABLE_L1()
  {
    ip_tag = 0;
    last_page = 0;
    last_cl_offset = 0;
    last_stride = 0;
    ip_valid = 0;
    signature = 0;
    conf = 0;
    str_dir = 0;
    str_valid = 0;
    str_strength = 0;
  };
};

/*
 * Delta prediction table
 *
 * */

class DELTA_PRED_TABLE
{
public:
  int delta;
  int conf;

  DELTA_PRED_TABLE()
  {
    delta = 0;
    conf = 0;
  };
};

IP_TABLE_L1 trackers_l1[NUM_IP_TABLE_L1_ENTRIES];
DELTA_PRED_TABLE DPT_l1[4096];
uint64_t ghb_l1[NUM_GHB_ENTRIES];

SequiturPredictor sequitur_predictor;
uint64_t prev_cpu_cycle;
uint64_t num_misses;
float mpkc = {0};
// int spec_nl = {0};

int pf_cs = 0, pf_nl = 0, pf_gs = 0, pf_cplx = 0, pf_seq = 0, pf_rctp = 0;
int pf_cs_useful = 0, pf_nl_useful = 0, pf_gs_useful = 0, pf_cplx_useful = 0, pf_seq_useful = 0, pf_rctp_useful = 0;
int pf_cs_not_useful = 0, pf_nl_not_useful = 0, pf_gs_not_useful = 0, pf_cplx_not_useful = 0, pf_seq_not_useful = 0, pf_rctp_not_useful = 0;
int pf_cs_hit = 0, pf_nl_hit = 0, pf_gs_hit = 0, pf_cplx_hit = 0;
int pf_cs_fill = 0, pf_nl_fill = 0, pf_gs_fill = 0, pf_cplx_fill = 0, pf_seq_fill = 0, pf_rctp_fill = 0;
int pf_cs_lc = 0, pf_nl_lc = 0, pf_gs_lc = 0, pf_cplx_lc = 0, pf_seq_lc = 0, pf_rctp_lc = 0;

/***************Updating the signature*************************************/
uint16_t update_sig_l1(uint16_t old_sig, int delta)
{
  uint16_t new_sig = 0;
  int sig_delta = 0;

  // 7-bit sign magnitude form, since we need to track deltas from +63 to -63
  sig_delta = (delta < 0) ? (((-1) * delta) + (1 << 6)) : delta;
  new_sig = ((old_sig << 1) ^ sig_delta) & 0xFFF; // 12-bit signature

  return new_sig;
}

/****************Encoding the metadata***********************************/
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

bool strided_buffer = false;
uint64_t strided_buffer_stride = 0;

void check_for_stream_l1(int index, uint64_t cl_addr)
{
  int pos_count = 0, neg_count = 0, count = 0;
  uint64_t check_addr = cl_addr;
  uint64_t cc_time = 0;
  strided_buffer = false;
  int stride_count = 0;
  int stride = check_addr - ghb_l1[0]; // First element's difference
  for (int i = 1; i < NUM_GHB_ENTRIES; i++) {
    if (abs(ghb_l1[i] - ghb_l1[i - 1]) == stride) {
      stride_count++;
    }
  }
  if (stride_count >= (NUM_GHB_ENTRIES * 3) / 4) {
    // std::cout << " Strided Buffer detected" << std::endl;
    strided_buffer = true;
    strided_buffer_stride = stride;
  }

  // check for +ve stream
  for (int i = 0; i < NUM_GHB_ENTRIES; i++) {
    check_addr--;
    for (int j = 0; j < NUM_GHB_ENTRIES; j++)
      if (check_addr == ghb_l1[j]) {
        // cc_time -= ghb_l1_cc[j];
        pos_count++;
        break;
      }
  }

  check_addr = cl_addr;
  // check for -ve stream
  for (int i = 0; i < NUM_GHB_ENTRIES; i++) {
    check_addr++;
    for (int j = 0; j < NUM_GHB_ENTRIES; j++)
      if (check_addr == ghb_l1[j]) {
        neg_count++;
        break;
      }
  }

  if (pos_count > neg_count) { // stream direction is +ve
    trackers_l1[index].str_dir = 1;
    count = pos_count;
  } else { // stream direction is -ve
    trackers_l1[index].str_dir = 0;
    count = neg_count;
  }

  if (count > NUM_GHB_ENTRIES / 2) { // stream is detected
    trackers_l1[index].str_valid = 1;
    if (count >= (NUM_GHB_ENTRIES * 3) / 4) // stream is classified as strong if more than 3/4th entries belong to stream
      trackers_l1[index].str_strength = 1;
  } else {
    if (trackers_l1[index].str_strength == 0) // if identified as weak stream, we need to reset
      trackers_l1[index].str_valid = 0;
  }
}

/**************************Updating confidence for the CS class****************/
int update_conf(int stride, int pred_stride, int conf)
{
  if (stride == pred_stride) { // use 2-bit saturating counter for confidence
    conf++;
    if (conf > 3)
      conf = 3;
  } else {
    conf--;
    if (conf < 0)
      conf = 0;
  }

  return conf;
}

uint64_t prev_stride = 0;

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
  static constexpr int NUM_MSHR_BINS = 2;
  static constexpr int NUM_PFQ_BINS = 2;
  static constexpr int NUM_USEFULNESS_BINS = 2;
  static constexpr int NUM_STATES = NUM_MSHR_BINS * NUM_PFQ_BINS * NUM_USEFULNESS_BINS; // 8 states

  static constexpr int NUM_ACTIONS = 16; // 16 smart actions as defined earlier

  int8_t Q[NUM_STATES][NUM_ACTIONS];

  const float alpha = 0.2f; // learning rate
  const float gamma = 0.9f; // discount factor
  float epsilon = 1.0f;     // exploration rate (can decay over time)

  PrefetcherQLearningController()
  {
    for (int s = 0; s < NUM_STATES; ++s) {
      for (int a = 0; a < NUM_ACTIONS; ++a) {
        Q[s][a] = 10; // Warm start Q-table with positive bias
      }
    }
  }

  int quantize_mshr(float mshr_ratio) { return (mshr_ratio < 0.5f) ? 0 : 1; }

  int quantize_pfq(float pfq_ratio) { return (pfq_ratio < 0.5f) ? 0 : 1; }

  int quantize_usefulness(float usefulness_ratio) { return (usefulness_ratio < 0.5f) ? 0 : 1; }

  int get_state_index(int mshr_bin, int pfq_bin, int usefulness_bin) { return (mshr_bin << 2) | (pfq_bin << 1) | usefulness_bin; }

  int select_action(int state)
  {
    if ((float)(rand() % 100) / 100.0f < epsilon) {
      // Biased exploration: prefer aggressive actions (action_id 8-15)
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

    // Scale reward appropriately (softened reward)
    int scaled_reward = static_cast<int>(reward * 127.0f);

    int update = static_cast<int>(current_q + alpha * (scaled_reward + gamma * max_future_q - current_q));

    // Clip to int8_t range
    if (update > 127)
      update = 127;
    if (update < -128)
      update = -128;

    Q[old_state][action] = static_cast<int8_t>(update);
  }

  // Helper for calculating soft reward
  float calculate_reward(int useful_prefetches, int not_useful_prefetches)
  {
    int total = useful_prefetches + not_useful_prefetches;
    if (total == 0)
      return 0.0f;
    return static_cast<float>((useful_prefetches) + 10) / (total + 10); // soft reward with +10 stabilizer
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

  const int action_table[16][6] = {
      // NL, GS, CS, CPLX, SEQ, RCTP
      {0, 0, 0, 0, 0, 0}, // Action 0: Everything OFF
      {1, 1, 1, 0, 0, 0}, // Action 1: Light NL+GS+CS
      {2, 2, 2, 0, 0, 0}, // Action 2: Medium NL+GS+CS
      {3, 3, 3, 0, 0, 0}, // Action 3: Heavy NL+GS+CS
      {1, 0, 0, 1, 0, 0}, // Action 4: Light NL + CPLX
      {2, 0, 0, 2, 0, 0}, // Action 5: Medium NL + CPLX
      {0, 1, 0, 1, 0, 0}, // Action 6: Light GS + CPLX
      {0, 2, 1, 2, 0, 0}, // Action 7: Medium GS + CS + CPLX
      {1, 1, 2, 0, 0, 0}, // Action 8: NL + GS + stronger CS
      {1, 2, 2, 0, 0, 0}, // Action 9: NL + strong GS + CS
      {2, 2, 1, 1, 0, 0}, // Action 10: balanced NL+GS, weaker CPLX
      {1, 3, 0, 1, 0, 0}, // Action 11: light NL + aggressive GS + CPLX
      {2, 1, 2, 0, 0, 0}, // Action 12: stronger CS with moderate NL/GS
      {3, 1, 1, 0, 0, 0}, // Action 13: heavy NL, light GS
      {1, 0, 2, 0, 0, 0}, // Action 14: NL + strong CS
      {3, 0, 1, 0, 0, 0}  // Action 15: heavy NL + light CS
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

void ipcp::prefetcher_initialize()
{
  // std::cout<< this->intern_->sim_stats.misses({access_type::PREFETCH, miss});
}

uint32_t ipcp::prefetcher_cache_operate(champsim::address addr, champsim::address ip, uint8_t cache_hit, bool useful_prefetch, access_type type,
                                        uint32_t metadata_in)
{
  if (cache_hit == 0)
    num_misses += 1;

  if (this->intern_->current_cycle() < 1000000) {
    ql_controller.epsilon = 1.0f; // Full random exploration
  } else {
    ql_controller.epsilon = 0.3f;
  }

  bool pf_flag = false;

  // uint64_t usefulness = this->intern_->sim_stats.pf_useful > 0 && this->intern_->sim_stats.pf_issued > 0
  //                           ? this->intern_->sim_stats.pf_useful / this->intern_->sim_stats.pf_issued
  //                           : 0.0;

  uint64_t curr_page = addr.to<uint64_t>() >> LOG2_PAGE_SIZE;
  uint64_t cl_addr = addr.to<uint64_t>() >> LOG2_BLOCK_SIZE;
  uint64_t cl_offset = (addr.to<uint64_t>() >> LOG2_BLOCK_SIZE) & 0x3F;
  uint16_t signature = 0, last_signature = 0;
  int num_prefs = 0;
  uint32_t metadata = 0;
  uint16_t ip_tag = (ip.to<uint64_t>() >> NUM_IP_INDEX_BITS) & ((1 << NUM_IP_TAG_BITS) - 1);
  int index = ip.to<uint64_t>() & ((1 << NUM_IP_INDEX_BITS) - 1);

  // const float MSHR_LOW_THRESHOLD = 0.3;
  // const float MSHR_HIGH_THRESHOLD = 0.7;
  // const float PFQ_LOW_THRESHOLD = 0.3;
  // const float PFQ_HIGH_THRESHOLD = 0.7;

  // bool mshr_low = (mshr_ratio < MSHR_LOW_THRESHOLD);
  // bool mshr_high = (mshr_ratio > MSHR_HIGH_THRESHOLD);
  // bool pfq_low = (pfq_ratio < PFQ_LOW_THRESHOLD);
  // bool pfq_high = (pfq_ratio > PFQ_HIGH_THRESHOLD);

  int prefetch_degree = 0;

  // if (mshr_high && pfq_high) {
  //   prefetch_degree = 1; // System heavily loaded — very cautious
  // } else if ((mshr_high && pfq_low) || (mshr_low && pfq_high)) {
  //   prefetch_degree = 2; // Partial pressure — moderate prefetching
  // } else {
  //   prefetch_degree = 3; // System idle — aggressive prefetching
  // }

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
    int usefulness_bin = ql_controller.quantize_usefulness(usefulness_ratio);

    int current_state = ql_controller.get_state_index(mshr_bin, pfq_bin, usefulness_bin);

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

  uint64_t set = this->intern_->get_set(addr.to<uint64_t>());
  uint64_t way = this->intern_->get_way(addr.to<uint64_t>(), set);
  champsim::cache_block cache_block = this->intern_->block[set * way];

  if (useful_prefetch && cache_block.pf_metadata != 0) {
    // std::cout << "[OPERATE]Cache :" << this->intern_->sim_stats.name << "     Address :" << addr << "    Metadata :" << cache_block.pf_metadata
    //           << "    Cache hit :" << (bool)cache_hit << "    Hits/Misses:" << this->intern_->sim_stats.pf_useful / this->intern_->sim_stats.pf_useless
    //           << std::endl;

    std::cout << "[OPERATE]Cache :" << this->intern_->sim_stats.name << "     Address :" << addr << "    Metadata :" << cache_block.pf_metadata
              << "    Occupancy ratio :" << this->intern_->get_pq_occupancy_ratio()[2] << std::endl;

    switch (cache_block.pf_metadata) {
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

    switch (cache_block.pf_metadata) {
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

  // calculate the index bit
  // int index = ip.to<uint64_t>() & ((1 << NUM_IP_INDEX_BITS) - 1);
  // std::cout<< "IP Tag :" <<ip_tag << "    index :" << index <<std::endl;

  if (trackers_l1[index].ip_tag != ip_tag) { // new/conflict IP
    if (trackers_l1[index].ip_valid == 0) {  // if valid bit is zero, update with latest IP info
      trackers_l1[index].ip_tag = ip_tag;
      trackers_l1[index].last_page = curr_page;
      trackers_l1[index].last_cl_offset = cl_offset;
      trackers_l1[index].last_stride = 0;
      trackers_l1[index].signature = 0;
      trackers_l1[index].conf = 0;
      trackers_l1[index].str_valid = 0;
      trackers_l1[index].str_strength = 0;
      trackers_l1[index].str_dir = 0;
      trackers_l1[index].ip_valid = 1;
    } else { // otherwise, reset valid bit and leave the previous IP as it is
      trackers_l1[index].ip_valid = 0;
    }

    // issue a next line prefetch upon encountering new IP
    // uint64_t pf_address = ((addr.to<uint64_t>() >> LOG2_BLOCK_SIZE) + 1) << LOG2_BLOCK_SIZE; // BASE NL=1, changing it to 3
    // // metadata = encode_metadata(1, NL_TYPE, spec_nl);
    // pf_nl_lc++;
    // if (prefetch_line(champsim::address{pf_address}, true, 1)) {
    //   pf_nl++;
    //   pf_flag = true;
    // }
    // return metadata_in;
  } else { // if same IP encountered, set valid bit
    trackers_l1[index].ip_valid = 1;
  }

  // calculate the stride between the current address and the last address
  int64_t stride = 0;

  stride = cl_offset - trackers_l1[index].last_cl_offset;

  // don't do anything if same address is seen twice in a row
  if (stride == 0)
    return metadata_in;

  // page boundary learning
  if (curr_page != trackers_l1[index].last_page) {
    if (stride < 0)
      stride += 64;
    else
      stride -= 64;
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
  DPT_l1[last_signature].conf = update_conf(stride, DPT_l1[last_signature].delta, DPT_l1[last_signature].conf);

  // update CPLX only if confidence is zero
  if (DPT_l1[last_signature].conf == 0)
    DPT_l1[last_signature].delta = stride;

  // calculate and update new signature in IP table
  signature = update_sig_l1(last_signature, stride);
  trackers_l1[index].signature = signature;

  // check GHB for stream IP
  check_for_stream_l1(index, cl_addr);

  /**
   *
   * Global stream
   *
   */
  if (class_control_gs.enabled && trackers_l1[index].str_valid == 1) { // stream IP
    // for stream, prefetch with twice the usual degree
    prefetch_degree = class_control_gs.prefetch_degree;
    if (trackers_l1[index].str_strength == 1) {
      prefetch_degree = prefetch_degree * 3;
    } else {
      prefetch_degree = prefetch_degree * 2;
    }
    uint64_t pf_address;
    for (int i = 0; i < prefetch_degree; i++) {
      pf_address = 0;

      // if (strided_buffer) {
      //   if (trackers_l1[index].str_dir == 1) { // +ve stream
      //     pf_address = (cl_addr + i + strided_buffer_stride) << LOG2_BLOCK_SIZE;
      //   } else { // -ve stream
      //     pf_address = (cl_addr - i - strided_buffer_stride) << LOG2_BLOCK_SIZE;
      //   }
      // } else {
      if (trackers_l1[index].str_dir == 1) { // +ve stream
        pf_address = (cl_addr + i + 1) << LOG2_BLOCK_SIZE;
      } else { // -ve stream
        pf_address = (cl_addr - i - 1) << LOG2_BLOCK_SIZE;
      }
      // }

      // Check if prefetch address is in same 4 KB page
      if ((pf_address >> LOG2_PAGE_SIZE) != (addr.to<uint64_t>() >> LOG2_PAGE_SIZE)) {
        break;
      }
      pf_gs_lc++;
      if (prefetch_line(champsim::address{pf_address}, true, 2)) {
        pf_gs++;
        pf_flag = true;
      }
      // else {
      //   prefetch_line(champsim::address{pf_address}, false, 2);
      // }
      num_prefs++;
      SIG_DP(cout << "1, ");
    }

    // if (strided_buffer) {
    //   for (int i = 0; i < prefetch_degree; i++) {
    //     // pf_address = 0;

    //     if (trackers_l1[index].str_dir == 1) { // +ve stream
    //       pf_address = (cl_addr + prefetch_degree + i + strided_buffer_stride) << LOG2_BLOCK_SIZE;
    //     } else { // -ve stream
    //       pf_address = (cl_addr - i - prefetch_degree - strided_buffer_stride) << LOG2_BLOCK_SIZE;
    //     }

    //     // Check if prefetch address is in same 4 KB page
    //     if ((pf_address >> LOG2_PAGE_SIZE) != (addr.to<uint64_t>() >> LOG2_PAGE_SIZE)) {
    //       break;
    //     }
    //     // pf_gs_lc++;
    //     if (prefetch_line(champsim::address{pf_address}, false, 2)) {
    //       // pf_gs++;
    //     }
    //     // else {
    //     //   prefetch_line(champsim::address{pf_address}, false, 2);
    //     // }
    //     num_prefs++;
    //   }
    // }
  }

  /**
   *
   * Constant stride
   *
   */
  if (class_control_cs.enabled && trackers_l1[index].conf > 2 && trackers_l1[index].last_stride != 0 && (std::abs(trackers_l1[index].last_stride) <= 8)
      && trackers_l1[index].ip_tag == ip_tag) { // CS IP
    // std::cout << "[OPERATE]Cache :" << this->intern_->sim_stats.name << "     Address :" << addr << "    Metadata :" << cache_block.pf_metadata
    // << "    Cache hit :" << (bool)cache_hit << "    Last stride:" << trackers_l1[index].last_stride << std::endl;
    prefetch_degree = class_control_cs.prefetch_degree;

    for (int i = 0; i < prefetch_degree; i++) {
      uint64_t pf_address = (cl_addr + (trackers_l1[index].last_stride * (i + 1))) << LOG2_BLOCK_SIZE;
      // Check if prefetch address is in same 4 KB page
      if ((pf_address >> LOG2_PAGE_SIZE) != (addr.to<uint64_t>() >> LOG2_PAGE_SIZE)) {
        break;
      }
      pf_cs_lc++;
      if (prefetch_line(champsim::address{pf_address}, true, 3)) {
        pf_cs++;
        pf_flag = true;
      }
      // else {
      // prefetch_line(champsim::address{pf_address}, false, 3);
      // }
      num_prefs++;
      SIG_DP(cout << trackers_l1[cpu][index].last_stride << ", ");
    }
  }

  /**
   *
   * CPLX
   *
   */
  if (class_control_cplx.enabled && DPT_l1[signature].conf >= 0 && DPT_l1[signature].delta != 0) { // if conf>=0, continue looking for delta
    prefetch_degree = class_control_cplx.prefetch_degree;
    int pref_offset = 0, i = 0; // CPLX IP
    for (i = 0; i < prefetch_degree; i++) {
      pref_offset += DPT_l1[signature].delta;
      uint64_t pf_address = ((cl_addr + pref_offset) << LOG2_BLOCK_SIZE);

      // Check if prefetch address is in same 4 KB page
      if (((pf_address >> LOG2_PAGE_SIZE) != (addr.to<uint64_t>() >> LOG2_PAGE_SIZE)) || (DPT_l1[signature].conf == -1) || (DPT_l1[signature].delta == 0)) {
        // if new entry in DPT or delta is zero, break
        break;
      }

      // we are not prefetching at L2 for CPLX type, so encode delta as 0
      // metadata = encode_metadata(0, CPLX_TYPE, spec_nl);
      if (DPT_l1[signature].conf > 0) { // prefetch only when conf>0 for CPLX
        pf_cplx_lc++;
        if (prefetch_line(champsim::address{pf_address}, true, 4)) {
          pf_cplx++;
          pf_flag = true;
        }
        // else {
        //   prefetch_line(champsim::address{pf_address}, false, 4);
        // }
        num_prefs++;
        SIG_DP(cout << pref_offset << ", ");
      }
      signature = update_sig_l1(signature, DPT_l1[signature].delta);
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

      uint64_t pf_address = (cl_addr + delta) << LOG2_BLOCK_SIZE;

      // Check if prefetch address stays in same 4KB page
      if ((pf_address >> LOG2_PAGE_SIZE) != (addr.to<uint64_t>() >> LOG2_PAGE_SIZE))
        break;

      pf_seq_lc++;
      if (prefetch_line(champsim::address{pf_address}, true, 5)) {
        pf_seq++;
        num_prefs++;
        pf_flag = true;
      }

      issued++; // Increment prefetch issued count
    }
  }

  /**
   *
   * RCTP
   *
   */
  if (!pf_flag && class_control_rctp.enabled) { // RCTP enabled
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

            uint64_t pf_address = (cl_addr + delta) << LOG2_BLOCK_SIZE;

            if ((pf_address >> LOG2_PAGE_SIZE) != (addr.to<uint64_t>() >> LOG2_PAGE_SIZE))
              break;

            if (prefetch_line(champsim::address{pf_address}, true, 6)) {
              num_prefs++;
              issued_rctp_pfs++;
              pf_flag = true;
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
  if (class_control_nl.enabled && stride == 1) { // NL IP
    prefetch_degree = class_control_nl.prefetch_degree;

    for (int i = 0; i < prefetch_degree; i++) {
      uint64_t pf_address = ((addr.to<uint64_t>() >> LOG2_BLOCK_SIZE) + 1) << LOG2_BLOCK_SIZE;
      pf_nl_lc++;
      if (prefetch_line(pf_address, true, 1)) {
        pf_nl++;
      }
    }
  }

  SIG_DP(cout << endl);

  // update the IP table entries
  trackers_l1[index].last_cl_offset = cl_offset;
  trackers_l1[index].last_page = curr_page;

  // update GHB
  // search for matching cl addr
  int ghb_index = 0;
  for (ghb_index = 0; ghb_index < NUM_GHB_ENTRIES; ghb_index++)
    if (cl_addr == ghb_l1[ghb_index])
      break;
  // only update the GHB upon finding a new cl address
  if (ghb_index == NUM_GHB_ENTRIES) {
    uint64_t lstride = abs(cl_addr - ghb_l1[0]);
    if (strided_buffer_stride == lstride && strided_buffer) {
      for (int i = 0; i < NUM_GHB_ENTRIES; i++) {
        ghb_l1[i] = 0;
      }
      strided_buffer = false;
    } else {
      for (ghb_index = NUM_GHB_ENTRIES - 1; ghb_index > 0; ghb_index--)
        ghb_l1[ghb_index] = ghb_l1[ghb_index - 1];
    }
    ghb_l1[0] = cl_addr;
  }

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

  return metadata_in;
}

uint32_t ipcp::prefetcher_cache_fill(champsim::address addr, long set, long way, uint8_t prefetch, champsim::address evicted_addr, uint32_t metadata_in)
{
  auto ways = this->intern_->get_way(addr.to<uint64_t>(), set);
  // this->intern_->'';
  if (prefetch) {
    // std::cout<< "[FILL]Cache :" << this->intern_->sim_stats.name << "     Address :" << addr << "    Metadata :" << (int)metadata_in << "    Evicted :" <<
    // evicted_addr << std::endl;

    switch (metadata_in) {
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