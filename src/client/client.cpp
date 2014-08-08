#include <cstdlib>
#include <iostream>
#include <boost/function.hpp>
#include <boost/bind.hpp>

#include "serialstream.h"
#include "TimeoutSerial.h"
#include "protocol.hpp"

//bool cmd_get_version_num(SerialStream & serial)
bool cmd_get_version_num(TimeoutSerial & serial)
{
   rdm::message::data_type::value_type device_addr =
         rdm::message::default_device_addr;
   rdm::message::data_type packet;

   if (!rdm::message::command::system::get_version_num(packet, device_addr))
   {
      return false;
   }

   std::vector<char> data_to_write;
   std::copy(packet.begin(), packet.end(), std::back_inserter(data_to_write));
   serial.write(data_to_write);

   rdm::message::data_type packet_reply;
   read_more:
   {
      std::vector<char> data_read;
      data_read = serial.read(1);

      std::copy(data_read.begin(), data_read.end(),
            std::back_inserter(packet_reply));

      // dbg
//      std::cout << "data size: " << std::dec << data_read.size() << std::endl;
//      for (const auto & item : data_read)
//      {
//         std::cout << std::hex;
//
//         std::cout << (int) item;
//         std::cout << std::endl;
//      }
//
//      std::cout << "packet size: " << std::dec << data_read.size() << std::endl;
//      for (const auto & item : packet_reply)
//      {
//         std::cout << std::hex;
//
//         std::cout << (int) item;
//         std::cout << std::endl;
//      }

//      std::copy(packet_reply.begin(), packet_reply.end(),
//            std::ostream_iterator<rdm::message::data_type::value_type>(
//                  std::cout, " "));

//std::cout << std::endl;

      rdm::message::reply::system::get_version_num version_num;
      if (!rdm::message::reply::decode(packet_reply, version_num))
      {
         BOOST_LOG_TRIVIAL(debug)<< "reading more...";
         goto read_more;
      }

//      std::stringstream ss;
//      std::copy(version_num.version().begin(), version_num.version().end(),
//            std::ostream_iterator<char>(ss));

      std::string version;
      // get rid of 0 or non print characters
      for (const auto & item : version_num.version())
      {
         if ('\0' != item)
         {
            version += std::iswprint(item) ? item : '.';
         }
      }
      BOOST_LOG_TRIVIAL(info)<< "version: '" << version << "'";
   }
   // serial << packet;
////   sleep(1);
//   std::string s;
//
//   serial >> s;
//   std::cout << s << std::endl;

//   read_again:
//   try
//   {
   //serial >> packet_reply;
//   }
//   catch (TimeoutException &)
//   {
//      std::cout << "size " << packet_reply.size() << std::endl;
//      if (0 == packet_reply.size())
//      {
//         goto read_again;
//      }
//   rdm::message::reply::get_version_num version_num;
//   if (!rdm::message::reply::decode(packet_reply, version_num))
//   {
////         throw;
//      return false;
//   }
//   std::cout << "version: '" << version_num.version() << "'" << std::endl;
////   }

   return true;
}

bool cmd_get_ser_num(TimeoutSerial & serial)
{
   rdm::message::data_type::value_type device_addr =
         rdm::message::default_device_addr;
   rdm::message::data_type packet;

   if (!rdm::message::command::system::get_ser_num(packet, device_addr))
   {
      return false;
   }

   std::vector<char> data_to_write;
   std::copy(packet.begin(), packet.end(), std::back_inserter(data_to_write));
   serial.write(data_to_write);

   rdm::message::data_type packet_reply;
   read_more:
   {
      std::vector<char> data_read;
      data_read = serial.read(1);

      std::copy(data_read.begin(), data_read.end(),
            std::back_inserter(packet_reply));

      rdm::message::reply::system::get_ser_num reply;
      if (!rdm::message::reply::decode(packet_reply, reply))
      {
         BOOST_LOG_TRIVIAL(debug)<< "reading more...";
         goto read_more;
      }

      std::string sernum;
      // get rid of 0 or non print characters
      for (const auto & item : reply.sernum())
      {
         if ('\0' != item)
         {
            sernum += std::iswprint(item) ? item : '.';
         }
      }
      BOOST_LOG_TRIVIAL(info)<< "sernum: '" << sernum << "'";
   }

   return true;
}

bool iso14443_type_b_transfer_cmd(TimeoutSerial & serial)
{
   rdm::message::data_type::value_type device_addr =
         rdm::message::default_device_addr;
   rdm::message::data_type packet;

   rdm::message::data_type cmd =
         { 0x00, 0x84, 0x00, 0x00, 0x08 }; // get random data
   if (!rdm::message::command::iso14443_type_b::transfer_cmd(packet, device_addr, cmd))
   {
      return false;
   }

   std::vector<char> data_to_write;
   std::copy(packet.begin(), packet.end(), std::back_inserter(data_to_write));
   serial.write(data_to_write);

   rdm::message::data_type packet_reply;
   read_more:
   {
      std::vector<char> data_read;
      data_read = serial.read(1);

      std::copy(data_read.begin(), data_read.end(),
            std::back_inserter(packet_reply));

      rdm::message::reply::iso14443_type_b::transfer_cmd reply;
      if (!rdm::message::reply::decode(packet_reply, reply))
      {
         BOOST_LOG_TRIVIAL(debug)<< "reading more...";
         goto read_more;
      }

      if (rdm::message::reply::status::command_ok != reply.status())
      {
         BOOST_LOG_TRIVIAL(warning)<< "reply status is not ok: " << rdm::message::reply::status_to_str(reply.status());
         BOOST_LOG_TRIVIAL(warning)<< "reply status code: " << rdm::message::reply::status_to_str(reply.status_code());
         //BOOST_LOG_TRIVIAL(warning)<< "reply status code: " << reply.status_code();
         //std::cout << reply.status_code();
         return false;
      }

      BOOST_LOG_TRIVIAL(info)<< "reply size: '" << reply.data_.size() << "'";
   }

   return true;
}

bool iso14443_type_a_transfer_cmd(TimeoutSerial & serial)
{
   rdm::message::data_type::value_type device_addr =
         rdm::message::default_device_addr;
   rdm::message::data_type packet;

   rdm::message::data_type cmd =
         { 0x00, 0x84, 0x00, 0x00, 0x08 }; // ISO14443 APDU Command
   if (!rdm::message::command::mifare::transfer_cmd(packet, device_addr, rdm::message::mifare_no_transfer_crc, cmd))
   {
      return false;
   }

   std::vector<char> data_to_write;
   std::copy(packet.begin(), packet.end(), std::back_inserter(data_to_write));
   serial.write(data_to_write);

   rdm::message::data_type packet_reply;
   read_more:
   {
      std::vector<char> data_read;
      data_read = serial.read(1);

      std::copy(data_read.begin(), data_read.end(),
            std::back_inserter(packet_reply));

      rdm::message::reply::mifare::transfer_cmd reply;
      if (!rdm::message::reply::decode(packet_reply, reply))
      {
         BOOST_LOG_TRIVIAL(debug)<< "reading more...";
         goto read_more;
      }

      if (rdm::message::reply::status::command_ok != reply.status())
      {
         BOOST_LOG_TRIVIAL(warning)<< "reply status is not ok: " << rdm::message::reply::status_to_str(reply.status());
         BOOST_LOG_TRIVIAL(warning)<< "reply status code: " << rdm::message::reply::status_to_str(reply.status_code());
         //BOOST_LOG_TRIVIAL(warning)<< "reply status code: " << reply.status_code();
         //std::cout << reply.status_code();
         return false;
      }

      BOOST_LOG_TRIVIAL(info)<< "reply size: '" << reply.data_.size() << "'";
   }

   return true;
}

bool iso15693_transfer_cmd(TimeoutSerial & serial)
{
   rdm::message::data_type::value_type device_addr =
         rdm::message::default_device_addr;
   rdm::message::data_type packet;

   rdm::message::data_type cmd =
         { 0x02, 0x2B }; // Get The Card’s Information
   if (!rdm::message::command::iso15693::transfer_cmd(packet, device_addr, cmd))
   {
      return false;
   }

   std::vector<char> data_to_write;
   std::copy(packet.begin(), packet.end(), std::back_inserter(data_to_write));
   serial.write(data_to_write);

   rdm::message::data_type packet_reply;
   read_more:
   {
      std::vector<char> data_read;
      data_read = serial.read(1);

      std::copy(data_read.begin(), data_read.end(),
            std::back_inserter(packet_reply));

      rdm::message::reply::iso15693::transfer_cmd reply;
      if (!rdm::message::reply::decode(packet_reply, reply))
      {
         BOOST_LOG_TRIVIAL(debug)<< "reading more...";
         goto read_more;
      }

      if (rdm::message::reply::status::command_ok != reply.status())
      {
         BOOST_LOG_TRIVIAL(warning)<< "reply status is not ok: " << rdm::message::reply::status_to_str(reply.status());
         BOOST_LOG_TRIVIAL(warning)<< "reply status code: " << rdm::message::reply::status_to_str(reply.status_code());
         //BOOST_LOG_TRIVIAL(warning)<< "reply status code: " << reply.status_code();
         //std::cout << reply.status_code();
         return false;
      }

      BOOST_LOG_TRIVIAL(info)<< "reply size: '" << reply.data_.size() << "'";
   }

   return true;
}

bool mifare_get_ser_num(TimeoutSerial & serial)
{
   rdm::message::data_type::value_type device_addr =
         rdm::message::default_device_addr;
   rdm::message::data_type packet;

   if (!rdm::message::command::mifare::get_ser_num(packet, device_addr))
   {
      return false;
   }

   std::vector<char> data_to_write;
   std::copy(packet.begin(), packet.end(), std::back_inserter(data_to_write));
   serial.write(data_to_write);

   rdm::message::data_type packet_reply;
   read_more:
   {
      std::vector<char> data_read;
      data_read = serial.read(1);

      std::copy(data_read.begin(), data_read.end(),
            std::back_inserter(packet_reply));

      rdm::message::reply::mifare::get_ser_num reply;
      if (!rdm::message::reply::decode(packet_reply, reply))
      {
         BOOST_LOG_TRIVIAL(debug)<< "reading more...";
         goto read_more;
      }

      if (rdm::message::reply::status::command_ok != reply.status())
      {
         BOOST_LOG_TRIVIAL(warning)<< "reply status is not ok: " << rdm::message::reply::status_to_str(reply.status());
         BOOST_LOG_TRIVIAL(warning)<< "reply status code: " << rdm::message::reply::status_to_str(reply.status_code());
         //BOOST_LOG_TRIVIAL(warning)<< "reply status code: " << reply.status_code();
         //std::cout << reply.status_code();
         return false;
      }

      std::uint32_t sernum = 0;
      const std::size_t expected_reply_sernum_size = sizeof(sernum);
      const std::size_t received_reply_sernum_size = reply.sernum().size();
      if (received_reply_sernum_size == expected_reply_sernum_size)
      {
         //std::memcpy(&sernum, reply.sernum().b);
         std::uint32_t * psernum = &sernum;
         for (size_t idx = 0; idx < sizeof(sernum); ++idx)
         {
            psernum[idx] = reply.sernum()[idx];
         }

         BOOST_LOG_TRIVIAL(info)<< "card sernum: '" << sernum << "'";
      }
      else
      {
         std::stringstream ss;
         ss << std::hex << reply.sernum();
         BOOST_LOG_TRIVIAL(info)<< "card sernum: '" << ss.rdbuf() << "'";
         //BOOST_LOG_TRIVIAL(warning)<< "card sernum unexpected size";
      }
   }

   return true;
}

template<typename command>
void send_command(command cmd)
{
   for (size_t retry = 1; retry; --retry)
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
   serial.setTimeout(boost::posix_time::seconds(3));

   boost::function<bool()> get_version;
   get_version = boost::bind(cmd_get_version_num, boost::ref(serial));

   boost::function<bool()> get_sernum;
   get_sernum = boost::bind(cmd_get_ser_num, boost::ref(serial));

   boost::function<bool()> cmd_mifare_get_ser_num;
   cmd_mifare_get_ser_num = boost::bind(mifare_get_ser_num, boost::ref(serial));

   boost::function<bool()> cmd_iso14443_type_b_transfer_cmd;
   cmd_iso14443_type_b_transfer_cmd = boost::bind(iso14443_type_b_transfer_cmd, boost::ref(serial));

   boost::function<bool()> cmd_iso14443_type_a_transfer_cmd;
   cmd_iso14443_type_a_transfer_cmd = boost::bind(iso14443_type_a_transfer_cmd, boost::ref(serial));

   boost::function<bool()> cmd_iso15693_transfer_cmd;
   cmd_iso15693_transfer_cmd = boost::bind(iso15693_transfer_cmd, boost::ref(serial));

//   send_command(get_version);
//   send_command(get_sernum);
//   send_command(cmd_mifare_get_ser_num);
//   send_command(cmd_iso14443_type_b_transfer_cmd);
//   send_command(cmd_iso14443_type_a_transfer_cmd);
   send_command(cmd_iso15693_transfer_cmd);

   return EXIT_SUCCESS;
}
