#include "catch.hpp"
#include "mocks.hpp"

#include "champsim_constants.h"
#include "ptw.h"
#include "vmem.h"

#include <array>

extern bool warmup_complete[NUM_CPUS];

SCENARIO("The number of issued steps matches the virtual memory levels") {
  GIVEN("A 5-level virtual memory") {
    constexpr std::size_t levels = 5;
    VirtualMemory vmem{20, 1<<12, levels, 1, 200};
    do_nothing_MRC mock_ll;
    PageTableWalker uut{"600-uut-0", 0, 0, {{1,1,0}, {1,1,0}, {1,1,0}, {1,1,0}}, 1, 1, 1, 1, 0, &mock_ll, vmem};
    to_rq_MRP mock_ul{&uut};

    std::array<champsim::operable*, 3> elements{{&mock_ul, &uut, &mock_ll}};

    std::fill(std::begin(warmup_complete), std::end(warmup_complete), false);

    WHEN("The PTW receives a request") {
      PACKET test;
      test.address = 0xdeadbeef;
      test.v_address = test.address;
      test.cpu = 0;
      test.to_return = {&mock_ul};

      auto test_result = mock_ul.issue(test);
      REQUIRE(test_result);

      for (auto i = 0; i < 10000; ++i)
        for (auto elem : elements)
          elem->_operate();

      THEN("5 requests are issued") {
        REQUIRE(std::size(mock_ll.addresses) == levels);
        REQUIRE(mock_ul.packets.back().return_time > 0);
      }
    }
  }
}

SCENARIO("Issuing a PTW fills the PSCLs") {
  GIVEN("A 5-level virtual memory") {
    constexpr std::size_t levels = 5;
    VirtualMemory vmem{33, 1<<12, levels, 1, 200};
    do_nothing_MRC mock_ll;
    PageTableWalker uut{"600-uut-1", 0, 0, {{1,1,vmem.shamt(4)}, {1,1,vmem.shamt(3)}, {1,1,vmem.shamt(2)}, {1,1,vmem.shamt(1)}}, 1, 1, 1, 1, 0, &mock_ll, vmem};
    to_rq_MRP mock_ul{&uut};

    std::array<champsim::operable*, 3> elements{{&mock_ul, &uut, &mock_ll}};

    std::fill(std::begin(warmup_complete), std::end(warmup_complete), false);

    WHEN("The PTW receives a request") {
      PACKET test;
      test.address = 0xffff'ffff'ffff'ffff;
      test.v_address = test.address;
      test.cpu = 0;
      test.to_return = {&mock_ul};

      auto test_result = mock_ul.issue(test);
      REQUIRE(test_result);

      for (auto i = 0; i < 10000; ++i)
        for (auto elem : elements)
          elem->_operate();

      THEN("The PSCLs contain the request's address") {
        CHECK(uut.pscl.at(0).check_hit(test.address).has_value());
        CHECK(uut.pscl.at(1).check_hit(test.address).has_value());
        CHECK(uut.pscl.at(2).check_hit(test.address).has_value());
        CHECK(uut.pscl.at(3).check_hit(test.address).has_value());
      }
    }
  }
}

SCENARIO("PSCLs can reduce the number of issued translation requests") {
  GIVEN("A 5-level virtual memory and one issued packet") {
    constexpr std::size_t levels = 5;
    VirtualMemory vmem{33, 1<<12, levels, 1, 200};
    do_nothing_MRC mock_ll;
    PageTableWalker uut{"600-uut-2", 0, 0, {{1,1,vmem.shamt(4)}, {1,1,vmem.shamt(3)}, {1,1,vmem.shamt(2)}, {1,1,vmem.shamt(1)}}, 1, 1, 1, 1, 0, &mock_ll, vmem};
    to_rq_MRP mock_ul{&uut};

    std::array<champsim::operable*, 3> elements{{&mock_ul, &uut, &mock_ll}};

    std::fill(std::begin(warmup_complete), std::end(warmup_complete), false);

    PACKET seed;
    seed.address = 0xffff'ffff'ffff'ffff;
    seed.v_address = seed.address;
    seed.cpu = 0;
    seed.to_return = {&mock_ul};

    auto seed_result = mock_ul.issue(seed);
    REQUIRE(seed_result);

    for (auto i = 0; i < 10000; ++i)
      for (auto elem : elements)
        elem->_operate();

    WHEN("The PTW receives the same request") {
      mock_ll.addresses.clear();

      auto test_result = mock_ul.issue(seed);
      REQUIRE(test_result);

      for (auto i = 0; i < 10000; ++i)
        for (auto elem : elements)
          elem->_operate();

      THEN("1 request is issued") {
        REQUIRE(std::size(mock_ll.addresses) == 1);
        REQUIRE(mock_ul.packets.back().return_time > 0);
      }
    }

    WHEN("The PTW receives a nearby request") {
      mock_ll.addresses.clear();

      PACKET test = seed;
      test.address = 0xffff'ffff'ffc0'0000;
      test.v_address = test.address;
      auto test_result = mock_ul.issue(test);
      REQUIRE(test_result);

      for (auto i = 0; i < 10000; ++i)
        for (auto elem : elements)
          elem->_operate();

      THEN("2 requests are issued") {
        REQUIRE(std::size(mock_ll.addresses) == 2);
        REQUIRE(mock_ul.packets.back().return_time > 0);
      }
    }
  }
}
