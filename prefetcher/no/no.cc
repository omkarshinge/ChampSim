#include "no.h"
#include <iostream>
#include "cache.h"

uint32_t no::prefetcher_cache_operate(champsim::address addr, champsim::address ip, uint8_t cache_hit, bool useful_prefetch, access_type type,
                                      uint32_t metadata_in)
{
  // assert(addr == ip); // Invariant for instruction prefetchers
  
  // if(addr.operator==((champsim::address)0)){
  //   std::cout<< "PF FILL Address :" << addr << "    Metadata :" << metadata_in << std::endl;
  // }
  
  if(useful_prefetch){
    // std::cout<< "Address :" << addr << "    Metadata :" << metadata_in << "    Access type :" << (uint8_t)type << std::endl;
  } 
  return metadata_in;
}

uint32_t no::prefetcher_cache_fill(champsim::address addr, long set, long way, uint8_t prefetch, champsim::address evicted_addr, uint32_t metadata_in)
{
  // if(prefetch){
  //   std::cout<< "[FILL]Cache :" << this->intern_->sim_stats.name << "     Address :" << addr << "    Metadata :" << (int)metadata_in << "    Evicted :" << evicted_addr << std::endl;
  // } 
  return metadata_in;
}
