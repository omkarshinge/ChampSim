/***************************************************************************
For the Third Data Prefetching Championship - DPC3

Paper ID: #4
Instruction Pointer Classifying Prefetcher - IPCP

Authors:
Samuel Pakalapati - samuelpakalapati@gmail.com
Biswabandan Panda - biswap@cse.iitk.ac.in
***************************************************************************/

#include "ipcp.h"

#include <access_type.h>
#include <iostream>
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

enum IPCP_CLASSES { NL = 1, GS, CS, CPLX, SEQ };

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

  std::vector<int64_t> predict_next() {
    if (history_buffer.empty()) return {};

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

class IP_TABLE_L1
{
public:
  uint64_t ip_tag;
  uint64_t last_page;      // last page seen by IP
  uint64_t last_cl_offset; // last cl offset in the 4KB page
  int64_t last_stride;     // last delta observed
  uint16_t ip_valid;       // Valid IP or not
  int conf;                // CS conf
  uint16_t signature;      // CPLX signature
  uint16_t str_dir;        // stream direction
  uint16_t str_valid;      // stream valid
  uint16_t str_strength;   // stream strength

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

int pf_cs = 0, pf_nl = 0, pf_gs = 0, pf_cplx = 0, pf_seq = 0;
int pf_cs_useful = 0, pf_nl_useful = 0, pf_gs_useful = 0, pf_cplx_useful = 0, pf_seq_useful = 0;
int pf_cs_not_useful = 0, pf_nl_not_useful = 0, pf_gs_not_useful = 0, pf_cplx_not_useful = 0, pf_seq_not_useful = 0;
int pf_cs_hit = 0, pf_nl_hit = 0, pf_gs_hit = 0, pf_cplx_hit = 0;
int pf_cs_fill = 0, pf_nl_fill = 0, pf_gs_fill = 0, pf_cplx_fill = 0, pf_seq_fill = 0, pf_default_fill = 0;
int pf_cs_lc = 0, pf_nl_lc = 0, pf_gs_lc = 0, pf_cplx_lc = 0, pf_seq_lc = 0;

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

uint32_t ipcp::prefetcher_cache_operate(champsim::address addr, champsim::address ip, uint8_t cache_hit, bool useful_prefetch, access_type type,
                                        uint32_t metadata_in)
{
  // if(useful_prefetch){
  //   std::cout<< "[OPERATE]Cache :" << this->intern_->sim_stats.name << "     Address :" << addr << "    Metadata :" << (int)metadata_in << "    Cache hit :"
  //   << (int)cache_hit << std::endl;
  // }

  uint64_t set = this->intern_->get_set(addr.to<uint64_t>());
  uint64_t way = this->intern_->get_way(addr.to<uint64_t>(), set);
  champsim::cache_block cache_block = this->intern_->block[set * way];

  if (useful_prefetch && cache_block.pf_metadata != 0) {
    std::cout << "[OPERATE]Cache :" << this->intern_->sim_stats.name << "     Address :" << addr << "    Metadata :" << cache_block.pf_metadata
              << "    Cache hit :" << (bool)cache_hit << "    Access Type:" << (int)type << std::endl;

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
    default:
      break;
    }
  }

  uint64_t curr_page = addr.to<uint64_t>() >> LOG2_PAGE_SIZE;
  uint64_t cl_addr = addr.to<uint64_t>() >> LOG2_BLOCK_SIZE;
  uint64_t cl_offset = (addr.to<uint64_t>() >> LOG2_BLOCK_SIZE) & 0x3F;
  uint16_t signature = 0, last_signature = 0;
  int prefetch_degree = 0;
  // int spec_nl_threshold = 0;
  int num_prefs = 0;
  uint32_t metadata = 0;
  uint16_t ip_tag = (ip.to<uint64_t>() >> NUM_IP_INDEX_BITS) & ((1 << NUM_IP_TAG_BITS) - 1);

  prefetch_degree = 3;
  // spec_nl_threshold = 15;

  // update miss counter
  if (cache_hit == 0)
    num_misses += 1;

  // update spec nl bit when num misses crosses certain threshold
  // if(num_misses[cpu] == 256){
  //     mpkc[cpu] = ((float) num_misses[cpu]/(current_core_cycle[cpu]-prev_cpu_cycle[cpu]))*1000;
  //     prev_cpu_cycle[cpu] = current_core_cycle[cpu];
  //     if(mpkc[cpu] > spec_nl_threshold)
  //         spec_nl[cpu] = 0;
  //     else
  //         spec_nl[cpu] = 1;
  //     num_misses[cpu] = 0;
  // }

  // calculate the index bit
  int index = ip.to<uint64_t>() & ((1 << NUM_IP_INDEX_BITS) - 1);
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
    uint64_t pf_address = ((addr.to<uint64_t>() >> LOG2_BLOCK_SIZE) + 1) << LOG2_BLOCK_SIZE; // BASE NL=1, changing it to 3
    // metadata = encode_metadata(1, NL_TYPE, spec_nl);
    pf_nl_lc++;
    if (prefetch_line(champsim::address{pf_address}, true, 1)) {
      pf_nl++;
    }
    // else {
    //   prefetch_line(champsim::address{pf_address}, false, 1);
    // }
    return metadata_in;
  } else { // if same IP encountered, set valid bit
    trackers_l1[index].ip_valid = 1;
  }

  // calculate the stride between the current address and the last address
  int64_t stride = 0;
  // if (cl_offset > trackers_l1[cpu][index].last_cl_offset)
  //     stride = cl_offset - trackers_l1[cpu][index].last_cl_offset;
  // else {
  //     stride = trackers_l1[cpu][index].last_cl_offset - cl_offset;
  //     stride *= -1;
  // }
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

  SIG_DP(cout << ip << ", " << cache_hit << ", " << cl_addr << ", " << addr << ", " << stride << "; ";
         cout << last_signature << ", " << DPT_l1[cpu][last_signature].delta << ", " << DPT_l1[cpu][last_signature].conf << "; ";
         cout << trackers_l1[cpu][index].last_stride << ", " << stride << ", " << trackers_l1[cpu][index].conf << ", " << "; ";);

  if (trackers_l1[index].str_valid == 1) { // stream IP
    // for stream, prefetch with twice the usual degree

    if (strided_buffer) {
      prefetch_degree = prefetch_degree * 3;
    } else {
      prefetch_degree = prefetch_degree * 2;
    }
    uint64_t pf_address;
    for (int i = 0; i < prefetch_degree; i++) {
      pf_address = 0;

      if (strided_buffer) {
        if (trackers_l1[index].str_dir == 1) { // +ve stream
          pf_address = (cl_addr + i + strided_buffer_stride) << LOG2_BLOCK_SIZE;
        } else { // -ve stream
          pf_address = (cl_addr - i - strided_buffer_stride) << LOG2_BLOCK_SIZE;
        }
      } else {
        if (trackers_l1[index].str_dir == 1) { // +ve stream
          pf_address = (cl_addr + i + 1) << LOG2_BLOCK_SIZE;
        } else { // -ve stream
          pf_address = (cl_addr - i - 1) << LOG2_BLOCK_SIZE;
        }
      }

      // Check if prefetch address is in same 4 KB page
      if ((pf_address >> LOG2_PAGE_SIZE) != (addr.to<uint64_t>() >> LOG2_PAGE_SIZE)) {
        break;
      }
      pf_gs_lc++;
      if (prefetch_line(champsim::address{pf_address}, true, 2)) {
        pf_gs++;
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

  else if (trackers_l1[index].conf > 1 && trackers_l1[index].last_stride != 0) { // CS IP
    for (int i = 0; i < prefetch_degree; i++) {
      uint64_t pf_address = (cl_addr + (trackers_l1[index].last_stride * (i + 1))) << LOG2_BLOCK_SIZE;

      // Check if prefetch address is in same 4 KB page
      if ((pf_address >> LOG2_PAGE_SIZE) != (addr.to<uint64_t>() >> LOG2_PAGE_SIZE)) {
        break;
      }

      // metadata = encode_metadata(trackers_l1[index].last_stride, CS_TYPE, spec_nl);
      pf_cs_lc++;
      if (prefetch_line(champsim::address{pf_address}, true, 3)) {
        pf_cs++;
      }
      // else {
      // prefetch_line(champsim::address{pf_address}, false, 3);
      // }
      num_prefs++;
      SIG_DP(cout << trackers_l1[cpu][index].last_stride << ", ");
    }
  }
  if (DPT_l1[signature].conf >= 0 && DPT_l1[signature].delta != 0) { // if conf>=0, continue looking for delta
    int pref_offset = 0, i = 0;                                      // CPLX IP
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

  if (num_prefs == 0) { // Sequitur fallback before NL
    std::vector<int64_t> preds = sequitur_predictor.predict_next();
    for (auto delta : preds) {
      uint64_t pf_address = (cl_addr + delta) << LOG2_BLOCK_SIZE;

      // Check if prefetch address stays in same 4KB page
      if ((pf_address >> LOG2_PAGE_SIZE) != (addr.to<uint64_t>() >> LOG2_PAGE_SIZE))
        break;
      pf_seq_lc++;
      if (prefetch_line(champsim::address{pf_address}, true, 5)) {
        // You can optionally add a counter pf_seq++ if you want
        pf_seq++;
        num_prefs++;
      }
    }
  }

  // if no prefetches are issued till now, speculatively issue a next_line prefetch
  if (num_prefs == 0 && stride == 1) { // NL IP
    uint64_t pf_address = ((addr.to<uint64_t>() >> LOG2_BLOCK_SIZE) + 1) << LOG2_BLOCK_SIZE;
    pf_nl_lc++;
    if (prefetch_line(pf_address, true, 1)) {
      pf_nl++;
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


  cout << "*** PF Filled ***" << endl;

  cout << "NL :" << pf_nl_fill << endl;
  cout << "GS :" << pf_gs_fill << endl;
  cout << "CS :" << pf_cs_fill << endl;
  cout << "CPLX :" << pf_cplx_fill << endl;
  cout << "SEQ :" << pf_cplx_fill << endl;

  cout << "*** Useful ***" << endl;
  cout << "NL:" << pf_nl_useful << endl;
  cout << "GS :" << pf_gs_useful << endl;
  cout << "CS :" << pf_cs_useful << endl;
  cout << "CPLX :" << pf_cplx_useful << endl;
  cout << "SEQ :" << pf_seq_useful << endl;

  cout << "*** Not Useful ***" << endl;
  cout << "NL:" << pf_nl_not_useful << endl;
  cout << "GS :" << pf_gs_not_useful << endl;
  cout << "CS :" << pf_cs_not_useful << endl;
  cout << "CPLX :" << pf_cplx_not_useful << endl;
  cout << "SEQ :" << pf_seq_not_useful << endl;

  cout << "*** Usefulness percentage ***" << endl;
  cout << "NL:" << pf_nl_useful / pf_nl_not_useful << endl;
  cout << "GS :" << pf_gs_useful / pf_gs_not_useful << endl;
  cout << "CS :" << pf_cs_useful / pf_cs_not_useful << endl;
  cout << "CPLX :" << pf_cplx_useful / pf_cplx_not_useful << endl;
  cout << "SEQ :" << pf_seq_useful / pf_seq_not_useful << endl;

  cout << "*************************" << endl;
}