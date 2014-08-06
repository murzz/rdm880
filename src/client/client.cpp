#include <cstdlib>
#include <iostream>

#include "serialstream.h"
#include "TimeoutSerial.h"
#include "protocol.hpp"

bool cmd_get_version_num(SerialStream & serial)
//bool cmd_get_version_num(TimeoutSerial & serial )
{
   rdm::message::data_type::value_type device_addr = rdm::message::default_device_addr;
   rdm::message::data_type packet;
   rdm::message::data_type packet_reply;

   if (!rdm::message::command::get_version_num(packet, device_addr))
   {
      return false;
   }

   serial << packet;
////   sleep(1);
//   std::string s;
//
//   serial >> s;
//   std::cout << s << std::endl;

   read_again:
   try
   {
      serial >> packet_reply;
   }
   catch (TimeoutException &)
   {
      std::cout << "size " << packet_reply.size() << std::endl;
      if (0 == packet_reply.size())
      {
         goto read_again;
      }
      rdm::message::reply::get_version_num version_num;
      if (!rdm::message::reply::decode(packet_reply, version_num))
      {
         throw;
         //return false;
      }
      std::cout << "version: '" << version_num.version() << "'" << std::endl;
   }

   return true;
}

int main(int argc, char **argv)
{
   SerialOptions options;

   if (argc > 1)
   {
      options.setDevice(argv[1]);
   }
   else
   {
      options.setDevice("/dev/ttyUSB0");
   }
   options.setBaudrate(115200);
   options.setTimeout(boost::posix_time::seconds(1));

   SerialStream serial(options);
   serial.exceptions(std::ios::badbit | std::ios::failbit); //Important!

   //TimeoutSerial serial("/dev/ttyUSB0",115200);
   //serial.setTimeout(boost::posix_time::seconds(5));

   for (size_t retry = 3; retry; --retry)
   {
      try
      {
         if (cmd_get_version_num(serial))
         {
            // stop retrying on success
            break;
         }
      }
      catch (TimeoutException &)
      {
         //serial.clear(); //Don't forget to clear error flags after a timeout
         std::cerr << "Timeout occurred, retrying..." << std::endl;
      }
      catch (...)
      {
         //serial.clear(); //Don't forget to clear error flags after a timeout
         std::cerr << "Unexpected exception, retrying..." << std::endl;
      }

   }

   return EXIT_SUCCESS;
}
