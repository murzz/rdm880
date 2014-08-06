#pragma once

#include <boost/test/unit_test.hpp>

#include "protocol.hpp"

BOOST_AUTO_TEST_CASE( set_address )
{
   // setup
   const rdm::message::data_type::value_type device_addr = 0x00;
   const rdm::message::data_type::value_type device_addr_new = 0x02;
   const rdm::message::data_type::value_type reply_status = to_integral(rdm::message::reply::status::command_ok);

   const rdm::message::data_type cmd_expected =
         { 0xAA, device_addr, 0x02, 0x80, device_addr_new, 0x80, 0xBB };

   const rdm::message::data_type reply_expected =
         { 0xAA, device_addr, 0x02, reply_status, device_addr_new, 0x00, 0xBB };

   // command
   rdm::message::data_type cmd_encoded;
   rdm::message::command::set_address(cmd_encoded, device_addr, device_addr_new);

   BOOST_CHECK_EQUAL_COLLECTIONS(cmd_encoded.begin(), cmd_encoded.end(),
         cmd_expected.begin(), cmd_expected.end());

   // reply
   rdm::message::reply::set_address reply_decoded;
   rdm::message::reply::type & generic_reply = dynamic_cast<rdm::message::reply::type &>(reply_decoded);
   rdm::message::reply::decode(reply_expected, generic_reply);

   BOOST_CHECK_EQUAL(reply_decoded.device_addr(), device_addr_new);
   BOOST_CHECK_EQUAL(to_integral(reply_decoded.status()), reply_status);
}
