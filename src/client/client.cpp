#include <cstdlib>
#include <iostream>

#include <boost/function.hpp>
#include <boost/bind.hpp>

#include <boost/log/trivial.hpp>

#include "serialstream.h"
#include "TimeoutSerial.h"
#include "rdm.hpp"

template<typename serial_device_type, typename cmd_encoder, typename reply_type>
bool send_receive(serial_device_type & serial, cmd_encoder encoder, reply_type & reply)
{
   rdm::message::data_type::value_type device_addr =
         rdm::message::default_device_addr;
   rdm::message::data_type packet;

   if (!encoder(packet, device_addr))
   {
      return false;
   }

   std::vector<char> data_to_write;
   std::copy(packet.begin(), packet.end(), std::back_inserter(data_to_write));
   serial.write(data_to_write);

   // reading by byte trying to decode it each time.
   // read more if decode failed
   // stop reading if decode succeeded
   rdm::message::data_type packet_reply;
   read_more:
   {
      std::vector<char> data_read;
      data_read = serial.read(1);

      std::copy(data_read.begin(), data_read.end(),
            std::back_inserter(packet_reply));

      if (!rdm::message::reply::decode(packet_reply, reply))
      {
         BOOST_LOG_TRIVIAL(debug)<< "reading more...";
         goto read_more; // Don't be scared
      }
   }

   if (rdm::message::reply::status::command_ok != reply.status())
   {
      BOOST_LOG_TRIVIAL(warning)<< "reply status is not ok: " << rdm::message::reply::status_to_str(reply.status());
      BOOST_LOG_TRIVIAL(warning)<< "reply status code: " << rdm::message::reply::status_to_str(reply.status_code());
      //BOOST_LOG_TRIVIAL(warning)<< "reply status code: " << reply.status_code();
      //std::cout << reply.status_code();
      return false;
   }

   return true;
}

bool cmd_get_version_num(TimeoutSerial & serial)
{
   auto encoder = boost::bind(rdm::message::command::system::get_version_num, _1, _2);

   rdm::message::reply::system::get_ser_num reply;
   if (!send_receive(serial, encoder, reply))
   {
      return false;
   }

   std::string version;
   // get rid of 0 or non print characters
   for (const auto & item : reply.sernum())
   {
      version += std::iswprint(item) ? item : '.';
   }
   BOOST_LOG_TRIVIAL(info)<< "version: '" << version << "'";

   return true;
}

bool cmd_get_ser_num(TimeoutSerial & serial)
{
   auto encoder = boost::bind(rdm::message::command::system::get_ser_num, _1, _2);

   rdm::message::reply::system::get_ser_num reply;
   if (!send_receive(serial, encoder, reply))
   {
      return false;
   }

   // dealing with reply
   std::string sernum;
   // get rid of 0 or non print characters
   for (const auto & item : reply.sernum())
   {
      sernum += std::iswprint(item) ? item : '.';
   }
   BOOST_LOG_TRIVIAL(info)<< "sernum: '" << sernum << "'";

   return true;
}

bool iso14443_type_b_transfer_cmd(TimeoutSerial & serial)
{
   rdm::message::data_type cmd =
         { 0x00, 0x84, 0x00, 0x00, 0x08 }; // get random data

   auto encoder = boost::bind(rdm::message::command::iso14443_type_b::transfer_cmd, _1, _2, cmd);

   rdm::message::reply::system::get_ser_num reply;
   if (!send_receive(serial, encoder, reply))
   {
      return false;
   }

   BOOST_LOG_TRIVIAL(info)<< "reply size: '" << reply.data_.size() << "'";
   return true;
}

bool select_app(TimeoutSerial & serial)
{
//   std::string app_id = "1TIC.ICA";
//   rdm::message::data_type apdu =
//         {
//               0x94, // CLA
//               0xA4, // INS
//               0x04, // P1
//               0x00, // P2
//         };
//   apdu.push_back(app_id.size());
//   std::copy(app_id.begin(), app_id.end(), std::back_inserter(apdu));

   rdm::message::data_type apdu =
         {
               0x94, // CLA
               0xA4, // INS
               0x04, // P1
               0x00, // P2
               0x8,
               0x31,
               0x54,
               0x49,
               0x43,
               0x2e,
               0x49,
               0x43,
               0x41,
         };

   auto encoder = boost::bind(rdm::message::command::iso14443_type_b::transfer_cmd, _1, _2, apdu);

   rdm::message::reply::system::get_ser_num reply;
   if (!send_receive(serial, encoder, reply))
   {
      return false;
   }

   BOOST_LOG_TRIVIAL(info)<< "reply size: '" << reply.data_.size() << "'";
   return true;
}

bool iso14443_type_a_transfer_cmd(TimeoutSerial & serial)
{
   rdm::message::data_type cmd =
         { 0x00, 0x84, 0x00, 0x00, 0x08 }; // ISO14443 APDU Command
   auto encoder = boost::bind(rdm::message::command::mifare::transfer_cmd, _1, _2,
         rdm::message::mifare_no_transfer_crc, cmd);

   rdm::message::reply::system::get_ser_num reply;
   if (!send_receive(serial, encoder, reply))
   {
      return false;
   }

   BOOST_LOG_TRIVIAL(info)<< "reply size: '" << reply.data_.size() << "'";
   return true;
}

bool iso15693_transfer_cmd(TimeoutSerial & serial)
{
   rdm::message::data_type cmd =
         { 0x02, 0x2B }; // Get The Card’s Information
   auto encoder = boost::bind(rdm::message::command::iso15693::transfer_cmd, _1, _2, cmd);

   rdm::message::reply::system::get_ser_num reply;
   if (!send_receive(serial, encoder, reply))
   {
      return false;
   }

   BOOST_LOG_TRIVIAL(info)<< "reply size: '" << reply.data_.size() << "'";

   return true;
}

bool mifare_get_ser_num(TimeoutSerial & serial)
{
   auto encoder = boost::bind(rdm::message::command::mifare::get_ser_num, _1, _2,
         rdm::message::mifare_request_idle, rdm::message::mifare_no_halt);

   rdm::message::reply::mifare::get_ser_num reply;
   if (!send_receive(serial, encoder, reply))
   {
      return false;
   }

   std::stringstream ss;
   ss << std::hex << reply.sernum();
   BOOST_LOG_TRIVIAL(info)<< "card sernum: '" << ss.rdbuf() << "'";

   return true;
}

bool reqb(TimeoutSerial & serial)
{
   rdm::message::data_type::value_type AFI = 0x00;
   rdm::message::data_type::value_type slot_num = 0x00;
   auto encoder = boost::bind(rdm::message::command::iso14443_type_b::request, _1, _2, AFI, slot_num);

   rdm::message::reply::mifare::get_ser_num reply;
   if (!send_receive(serial, encoder, reply))
   {
      return false;
   }

   BOOST_LOG_TRIVIAL(debug)<< "ATQB read successfully";

   return true;
}

template<typename command>
void send_command(command cmd)
{
   for (size_t retry = 3; retry; --retry)
   {
      try
      {
         if (cmd())
         {
            // stop retrying on success
            break;
         }
      } catch (TimeoutException &)
      {
         //   serial.clear(); //Don't forget to clear error flags after a timeout
         BOOST_LOG_TRIVIAL(warning)<< "Timeout occurred, retrying...";
      }
      catch (timeout_exception & e)
      {
         BOOST_LOG_TRIVIAL(warning)<< "Timeout occurred, retrying...";
      }
      catch ( std::ios_base::failure & e)
      {
         //   serial.clear(); //Don't forget to clear error flags after a timeout
         BOOST_LOG_TRIVIAL(warning) << "std::ios_base::failure::" << e.what() << ", retrying...";
      }
      catch (...)
      {
         //  serial.clear(); //Don't forget to clear error flags after a timeout
         BOOST_LOG_TRIVIAL(warning) << "Unexpected exception, retrying...";
      }
   }
}

int main(int argc, char **argv)
{
   std::string device = "/dev/ttyUSB0";
   if (argc > 1)
   {
      device = argv[1];
   }

//   SerialOptions options;
//   options.setDevice(device);
//   options.setBaudrate(115200);
//   options.setTimeout(boost::posix_time::seconds(3));
//
//   SerialStream serial(options);
//   serial.exceptions(std::ios::badbit | std::ios::failbit); //Important!

   TimeoutSerial serial(device, 115200);
   serial.setTimeout(boost::posix_time::seconds(5));

   auto get_version = boost::bind(cmd_get_version_num, boost::ref(serial));
   auto get_ser_num = boost::bind(cmd_get_ser_num, boost::ref(serial));
   auto cmd_mifare_get_ser_num = boost::bind(mifare_get_ser_num, boost::ref(serial));
   auto cmd_iso14443_type_b_transfer_cmd = boost::bind(iso14443_type_b_transfer_cmd, boost::ref(serial));
   auto cmd_iso14443_type_a_transfer_cmd = boost::bind(iso14443_type_a_transfer_cmd, boost::ref(serial));
   auto cmd_iso15693_transfer_cmd = boost::bind(iso15693_transfer_cmd, boost::ref(serial));
   auto cmd_reqb = boost::bind(reqb, boost::ref(serial));
   auto cmd_select_app = boost::bind(select_app, boost::ref(serial));

//   send_command(get_version);
//   send_command(get_sernum);
//   send_command(cmd_mifare_get_ser_num);
//   send_command(cmd_iso14443_type_b_transfer_cmd);
//   send_command(cmd_iso14443_type_a_transfer_cmd);
//   send_command(cmd_iso15693_transfer_cmd);
//   send_command(cmd_reqb);
   send_command(cmd_select_app);

   return EXIT_SUCCESS;
}
