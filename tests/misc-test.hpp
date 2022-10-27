#pragma once

#include <boost/test/unit_test.hpp>

#include <vector>
#include <rdm/misc.hpp>

BOOST_AUTO_TEST_CASE( mid_tests_generic )
{
   typedef std::vector<int> container;
   container initial =
         { 1, 2, 3, 4 };

   container::size_type pos = 1;
   container::difference_type len = 1;
   container expected =
         { 2 };

   container mided = mid(initial, pos, len);
   BOOST_CHECK_EQUAL_COLLECTIONS(mided.begin(), mided.end(), expected.begin(), expected.end());
}

BOOST_AUTO_TEST_CASE( mid_test_def_len )
{
   typedef std::vector<int> container;
   container initial =
         { 1, 2, 3, 4 };

   container::size_type pos = 2;
   container expected =
         { 3, 4 };

   container mided = mid(initial, pos);
   BOOST_CHECK_EQUAL_COLLECTIONS(mided.begin(), mided.end(), expected.begin(), expected.end());
}

BOOST_AUTO_TEST_CASE( mid_test_all_container )
{
   typedef std::vector<int> container;
   container initial =
         { 1, 2, 3, 4 };

   container::size_type pos = 0;
   container expected = initial;  // should be equal

   container mided = mid(initial, pos);
   BOOST_CHECK_EQUAL_COLLECTIONS(mided.begin(), mided.end(), expected.begin(), expected.end());
}

BOOST_AUTO_TEST_CASE( mid_test_pos_too_big )
{
   typedef std::vector<int> container;
   container initial =
         { 1, 2, 3, 4 };

   container::size_type pos = 10;
   container expected;  // should be empty because position is too high

   container mided = mid(initial, pos);
   BOOST_CHECK_EQUAL_COLLECTIONS(mided.begin(), mided.end(), expected.begin(), expected.end());
}

BOOST_AUTO_TEST_CASE( mid_test_len_is_zero )
{
   typedef std::vector<int> container;
   container initial =
         { 1, 2, 3, 4 };

   container::size_type pos = 1;
   container::difference_type len = 0;
   container expected;  // should be empty because len is zero

   container mided = mid(initial, pos, len);
   BOOST_CHECK_EQUAL_COLLECTIONS(mided.begin(), mided.end(), expected.begin(), expected.end());
}

BOOST_AUTO_TEST_CASE( mid_test_len_too_big )
{
   typedef std::vector<int> container;
   container initial =
         { 1, 2, 3, 4 };

   container::size_type pos = 1;
   container::difference_type len = initial.size() + 1;
   container expected =
         { 2, 3, 4 };  // should take all starting from pos because len is too big

   container mided = mid(initial, pos, len);
   BOOST_CHECK_EQUAL_COLLECTIONS(mided.begin(), mided.end(), expected.begin(), expected.end());
}
