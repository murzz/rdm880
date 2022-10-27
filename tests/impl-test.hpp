#pragma once

#include <sstream>
//#include <iostream>
#include <boost/test/unit_test.hpp>

#include <rdm/impl.hpp>

BOOST_AUTO_TEST_CASE( stream_test )
{
   rdm::message::data_type in =
         { 1, 2, 3, 4 };
   rdm::message::data_type out;

   std::stringstream ss;
   ss << in;
   ss >> out;
//   std::cout << in.size() << std::endl << out.size() <<std::endl;

   //std::copy(rhs.begin(), rhs.end(), std::ostream_iterator<rdm::message::data_type::value_type>(os));

//   std::cout << std::hex << ss << std::endl;
//   std::cout << std::hex <<  out << std::endl;

   BOOST_CHECK_EQUAL_COLLECTIONS(in.begin(), in.end(), out.begin(), out.end());
}

struct common
{
   const rdm::message::data_type::value_type stx = rdm::message::framing::value::STX;
   const rdm::message::data_type::value_type etx = rdm::message::framing::value::ETX;

   const rdm::message::data_type::value_type device_addr = rdm::message::default_device_addr;
   const rdm::message::data_type::value_type reply_status = to_integral(rdm::message::reply::status::command_ok);
   const rdm::message::data_type::value_type reply_result = to_integral(rdm::message::reply::status::set_ok);

   template<typename reply_type>
   void decode_and_check(reply_type & reply_decoded, const rdm::message::data_type & reply_expected) const
         {
      rdm::message::reply::type & generic_reply = dynamic_cast<rdm::message::reply::type &>(reply_decoded);
      rdm::message::reply::decode(reply_expected, generic_reply);

      BOOST_CHECK_EQUAL(to_integral(reply_decoded.status()), reply_status);
      BOOST_CHECK_EQUAL(reply_decoded.device_addr(), device_addr);
   }
};

BOOST_FIXTURE_TEST_SUITE( test_commands, common )

   BOOST_AUTO_TEST_CASE( set_address )
   {
      // setup
      const rdm::message::data_type::value_type cmd = to_integral(rdm::message::command::id::SetAddress);
      const rdm::message::data_type::value_type new_device_addr = 0x02;

      const rdm::message::data_type cmd_expected =
            { stx, device_addr, 0x02, cmd, new_device_addr, 0x80, etx };

      const rdm::message::data_type reply_expected =
            { stx, device_addr, 0x02, reply_status, new_device_addr, 0x00, etx };

      // command
      rdm::message::data_type cmd_encoded;
      rdm::message::command::system::set_address(cmd_encoded, device_addr, new_device_addr);

      BOOST_CHECK_EQUAL_COLLECTIONS(cmd_encoded.begin(), cmd_encoded.end(),
            cmd_expected.begin(), cmd_expected.end());

      // reply
      rdm::message::reply::system::set_address reply_decoded;
      decode_and_check(reply_decoded, reply_expected);

      BOOST_CHECK_EQUAL(reply_decoded.new_device_addr(), new_device_addr);
   }

   BOOST_AUTO_TEST_CASE( control_buzzer )
   {
      // setup
      const rdm::message::data_type::value_type cmd = to_integral(rdm::message::command::id::Control_Buzzer);
      const rdm::message::data_type::value_type buzz_duration = 0x18;
      const rdm::message::data_type::value_type buzz_count = 0x0a;

      const rdm::message::data_type cmd_expected =
            { stx, device_addr, 0x03, cmd, buzz_duration, buzz_count, 0x98, etx };

      const rdm::message::data_type reply_expected =
            { stx, device_addr, 0x02, reply_status, reply_result, 0x82, etx };

      // command
      rdm::message::data_type cmd_encoded;
      rdm::message::command::system::control_buzzer(cmd_encoded, device_addr, buzz_duration, buzz_count);

      BOOST_CHECK_EQUAL_COLLECTIONS(cmd_encoded.begin(), cmd_encoded.end(),
            cmd_expected.begin(), cmd_expected.end());

      // reply
      rdm::message::reply::system::control_buzzer reply_decoded;
      decode_and_check(reply_decoded, reply_expected);

      BOOST_CHECK_EQUAL(reply_decoded.result(), reply_result);
   }

   BOOST_AUTO_TEST_SUITE_END()
