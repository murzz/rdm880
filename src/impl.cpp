#include <limits>
#include <cstdint>
#include <sstream>
//#include <vector>
#include <deque>

#include <boost/log/trivial.hpp>
//#include <boost/iostreams/stream.hpp>

#include "rdm/misc.hpp"
#include "rdm/rdm.hpp"
#include "rdm/impl.hpp"

namespace rdm
{
   namespace message
   {
      namespace framing
      {
         data_type::value_type calculate_bcc(const data_type & packet, data_type::size_type start_idx,
               data_type::size_type size)
         {
            if (std::numeric_limits<data_type::size_type>::max() == size || packet.size() < size)
            {
               size = packet.size();
            }
            else
            {
               size += start_idx;
            }

            data_type::value_type bcc = 0;
            for (data_type::size_type idx = start_idx; idx < size; ++idx)
            {
               bcc ^= packet[idx];
            }
            return bcc;
         }

         bool is_sane(const data_type & frame)
         {
            if (frame.size() < framing::size::frame_min)
            {
               BOOST_LOG_TRIVIAL(warning)<< "frame size is too small: " << frame.size();
               return false;
            }

            if (framing::value::STX != frame.front() )
            {
               BOOST_LOG_TRIVIAL(warning) << "No STX";
               return false;
            }

            if (framing::value::ETX != frame.back())
            {
               BOOST_LOG_TRIVIAL(warning) << "No ETX";
               return false;
            }

            return true;
         }

         bool extract_bcc(const data_type & frame, data_type::value_type & bcc)
         {
            if (!is_sane(frame))
            {
               return false;
            }

            const data_type::size_type last_idx = frame.size() - 1;
            const data_type::size_type bcc_idx = last_idx - offset::bcc_reverse;

            bcc = frame.at(bcc_idx);
            return true;
         }

         bool encode(data_type & packet)
         {
            packet.push_back(calculate_bcc(packet));
            packet.push_back(framing::value::ETX);
            packet.push_front(framing::value::STX);
            return true;
         }

         bool verify(const data_type & frame)
         {
            // save frame bcc
            data_type::value_type extracted_bcc = 0;
            if (!extract_bcc(frame, extracted_bcc))
            {
               BOOST_LOG_TRIVIAL(warning)<< "Failed to extract BCC from frame";
               return false;
            }

            // calculate bcc excluding stx, bcc and etx framing bytes
            const data_type::size_type start_idx = size::stx;
            const data_type::size_type size = frame.size() - size::stx - size::etx - size::bcc;
            const data_type::value_type calculated_bcc = calculate_bcc(frame, start_idx, size);

            // verify bcc
            if (calculated_bcc != extracted_bcc)
            {
               BOOST_LOG_TRIVIAL(warning)<< "Calculated (" << calculated_bcc << ") and received (" << extracted_bcc
               << ") BCCs wont match";
               return false;
            }

            // verify data len (part of the message) by comparing with actual frame length
            const data_type::value_type data_len = frame.at(framing::offset::data_len);
            // we are expecting cmd/status byte and variable length data, if any
            // if cmd/status byte is there
            if (data_len < framing::size::data_len)
            {
               BOOST_LOG_TRIVIAL(warning)<< "data length is unexpected (frame is malformed)";
               return false;
            }

            // comparing lengths
            const data_type::size_type expected_frame_size = size::stx + size::device_addr + size::data_len + data_len
                  + size::bcc + size::etx;

            if (frame.size() != expected_frame_size)
            {
               BOOST_LOG_TRIVIAL(warning)<< "data length is unexpected (frame is malformed)";
               return false;
            }

            return true;
         }

         bool decode(data_type & frame)
         {
            if (!verify(frame))
            {
               return false;
            }

            // remove STX
            frame.pop_front();

            // chop BCC
            frame.pop_back();

            // chop ETX
            frame.pop_back();
            return true;
         }
      }

      namespace command
      {

         type::type(data_type::value_type device_addr) :
               device_addr_(device_addr), id_(command::id::Empty)
         {
         }

         type::~type()
         {
         }

      } // namespace command

      namespace reply
      {
         std::string status_to_str(const reply::status & status)
         {
            std::string status_str = "unknown";
            switch (status)
            {
            //System Error/Status Codes (0x00-0x0F)
            case reply::status::command_ok:
               status_str = "Command OK";
               break;
            case reply::status::command_failure:
               status_str = "Command FAILURE";
               break;
            case reply::status::set_ok:
               status_str = "SET OK";
               break;
            case reply::status::set_failure:
               status_str = "SET FAILURE";
               break;
            case reply::status::reader_reply_timeout:
               status_str = "Reader reply time out error";
               break;
            case reply::status::card_not_exists:
               status_str = "The card do not exist";
               break;
            case reply::status::card_response_error:
               status_str = "The data response from the card is error";
               break;
            case reply::status::unknown_parameter:
               status_str = "The parameter of the command or the Format of the command Error";
               break;
            case reply::status::internal_error:
               status_str = "Unknown Internal Error";
               break;
            case reply::status::unknown_command:
               status_str = "Reader received unknown command";
               break;

               //ISO14443 Error Codes：
            case reply::status::iso14443_init_val_error:
               status_str = "Some Error appear in the card InitVal process";
               break;
            case reply::status::iso14443_anticollision_error:
               status_str = "Get The Wrong Snr during anticollison loop";
               break;
            case reply::status::iso14443_auth_failure:
               status_str = "The authentication failure";
               break;

               //ISO15693  Error Codes：
            case reply::status::iso15693_unsupported_command:
               status_str = "The Card do not support this command";
               break;
            case reply::status::iso15693_format_error:
               status_str = "The Foarmat Of  The Command Erro";
               break;
            case reply::status::iso15693_unsupported_option:
               status_str = "Do not support Option mode";
               break;
            case reply::status::iso15693_block_not_exists:
               status_str = "The Block Do Not Exist";
               break;
            case reply::status::iso15693_object_locked:
               status_str = "The Object have been locked";
               break;
            case reply::status::iso15693_lock_failed:
               status_str = "The lock Operation Do Not Success";
               break;
            case reply::status::iso15693_failed:
               status_str = "The Operation Do Not Success";
               break;
            };

            return status_str;
         }

         type::type() :
               device_addr_(message::default_device_addr), status_(reply::status::command_failure)
         {
         }

         type::~type()
         {
         }

         const data_type::value_type & type::device_addr() const
         {
            return device_addr_;
         }

         const reply::status & type::status() const
         {
            return status_;
         }

         reply::status type::status_code() const
         {
            if (reply::status::command_ok == status_)
            {
               return reply::status::command_ok;
            }

            reply::status status_code = reply::status::command_ok;

            const auto dist_signed = std::distance(data_.begin(), data_.end());
            const data_type::size_type dist_unsigned = dist_signed < 0 ? 0 : dist_signed;
            if (dist_unsigned >= framing::offset::status_code + framing::size::status_code)
            {
               status_code = static_cast<message::reply::status>(data_.at(framing::offset::status_code));
            }

            return status_code;
         }

         const data_type & type::data() const
         {
            return data_;
         }

         data_type::value_type with_result::result()
         {
            return data_.at(framing::offset::reply_control_buzzer);
         }

         namespace system
         {
            data_type::value_type set_address::new_device_addr()
            {
               return data_.at(framing::offset::reply_device_addr);
            }

            message::baudrate set_baudrate::baudrate()
            {
               return static_cast<message::baudrate>(data_.at(framing::offset::reply_baudrate));
            }

            const data_type & get_version_num::version()
            {
               return data_;
            }

            data_type::value_type & get_ser_num::reported_device_addr()
            {
               return data_.at(framing::offset::reply_device_addr);
            }
            data_type get_ser_num::sernum()
            {
               return mid(data_, framing::offset::reply_sernum);
            }
         }   //namespace system

         namespace mifare
         {
            data_type::value_type & get_ser_num::flag()
            {
               return data_.at(framing::offset::reply_mifare_sernum_flag);
            }

            data_type get_ser_num::sernum()
            {
               return mid(data_, framing::offset::reply_mifare_sernum);
            }
         } // namespace mifare

         namespace iso14443_type_b
         {
            data_type request::atq()
            {
               return mid(data_, framing::offset::reply_atqb);
            }

            const data_type::value_type & request::reported_len()
            {
               return data_.at(framing::offset::reply_atqb_len);
            }

            data_type reset::sernum()
            {
               return mid(data_, framing::offset::reply_rstb);
            }

            const data_type::value_type & reset::reported_len()
            {
               return data_.at(framing::offset::reply_rstb_len);
            }
         } // namespace iso14443_type_b

         namespace iso15693
         {

         } // namespace iso15693

      } // namespace reply

      bool encode(data_type & packet, const command::type & command)
      {
         // sanity checks
         if (command.data_.size() > framing::size::data_field_max)
         {
            BOOST_LOG_TRIVIAL(warning)<< "Data size is larger then max allowed value";
            return false;
         }

         if (command::id::Empty == command.id_)
         {
            BOOST_LOG_TRIVIAL(warning) << "Command id is not initialized";
            return false;
         }

         data_type::value_type data_len = command.data_.size() + framing::size::cmd;

         packet.clear();

         packet.push_back(command.device_addr_);
         packet.push_back(data_len);
         packet.push_back(to_integral(command.id_));
         packet.insert(packet.end(), command.data_.begin(), command.data_.end());

         return framing::encode(packet);
      }

      bool decode(const data_type & packet, reply::type & reply)
      {
         if (!framing::verify(packet))
         {
            BOOST_LOG_TRIVIAL(warning)<<"failed to verify frame";

            return false;
         }

         reply.device_addr_ = packet.at(framing::offset::device_addr);
         reply.status_ = static_cast<message::reply::status>(packet.at(framing::offset::status));

         // variable size data, if any
         data_type::value_type data_len = packet.at(framing::offset::data_len);
         if (data_len > framing::size::data_len)
         {
            // excluding 'status' byte, which is first byte of data block
            reply.data_ = mid(packet, framing::offset::data, data_len - framing::size::data_len);
         }
         return true;
      }

      namespace command
      {
         namespace system
         {
            bool set_address(data_type & packet, const data_type::value_type & device_addr,
                  const data_type::value_type & new_device_addr)
            {
               command::type command(device_addr);
               command.id_ = command::id::SetAddress;
               command.data_.push_back(new_device_addr);

               return message::encode(packet, command);
            }

            bool set_baudrate(data_type & packet, const data_type::value_type & device_addr,
                  const message::baudrate & value)
            {
               command::type command(device_addr);
               command.id_ = command::id::SetBaudrate;
               command.data_.push_back(to_integral(value));

               return message::encode(packet, command);
            }

            bool get_ser_num(data_type & packet, const data_type::value_type & device_addr)
            {
               command::type command(device_addr);
               command.id_ = command::id::GetSerlNum;

               return message::encode(packet, command);
            }

            bool get_version_num(data_type & packet, const data_type::value_type & device_addr)
            {
               command::type command(device_addr);
               command.id_ = command::id::Get_VersionNum;

               return message::encode(packet, command);
            }

            bool control_led1(data_type & packet, const data_type::value_type & device_addr,
                  data_type::value_type blink_duration,
                  data_type::value_type blink_count)
            {
               command::type command(device_addr);
               command.id_ = command::id::Control_Led1;
               command.data_.push_back(blink_duration);
               command.data_.push_back(blink_count);

               return message::encode(packet, command);
            }

            bool control_led2(data_type & packet, const data_type::value_type & device_addr,
                  data_type::value_type blink_duration,
                  data_type::value_type blink_count)
            {
               command::type command(device_addr);
               command.id_ = command::id::Control_Led2;
               command.data_.push_back(blink_duration);
               command.data_.push_back(blink_count);

               return message::encode(packet, command);
            }

            bool control_buzzer(data_type & packet, const data_type::value_type & device_addr,
                  data_type::value_type buzz_duration,
                  data_type::value_type buzz_count)
            {
               command::type command(device_addr);
               command.id_ = command::id::Control_Buzzer;
               command.data_.push_back(buzz_duration);
               command.data_.push_back(buzz_count);

               return message::encode(packet, command);
            }
         } // namespace system

         namespace mifare
         {
            bool get_ser_num(data_type & packet, const data_type::value_type & device_addr,
                  data_type::value_type request_mode, data_type::value_type execute_halt)
            {
               command::type command(device_addr);
               command.id_ = command::id::MF_GET_SNR;
               command.data_.push_back(request_mode);
               command.data_.push_back(execute_halt);

               return message::encode(packet, command);
            }

            bool transfer_cmd(data_type & packet, const data_type::value_type & device_addr,
                  const data_type::value_type & crc_flag, const data_type & cmd)
            {
               command::type command(device_addr);
               command.id_ = command::id::ISO14443_TypeA_Transfer_Command;

               command.data_ = cmd;
               command.data_.push_front(cmd.size());
               command.data_.push_front(crc_flag);

               return message::encode(packet, command);
            }
         } // namespace mifare

         namespace iso14443_type_b
         {
            bool request(data_type & packet, const data_type::value_type & device_addr,
                  const data_type::value_type & AFI,
                  const data_type::value_type & slot_num)
            {
               command::type command(device_addr);
               command.id_ = command::id::Request_B;

               // values could be skipped from package, I guess some defaults are assumed by RDM
               command.data_.push_back(AFI);
               command.data_.push_back(slot_num);

               return message::encode(packet, command);
            }

            bool reset(data_type & packet, const data_type::value_type & device_addr)
            {
               command::type command(device_addr);
               command.id_ = command::id::Rst_TypeB;

               return message::encode(packet, command);
            }

            bool transfer_cmd(data_type & packet, const data_type::value_type & device_addr, const data_type & cmd)
            {
               command::type command(device_addr);
               command.id_ = command::id::ISO14443_TypeB_Transfer_Command;

               command.data_ = cmd;
               command.data_.push_front(cmd.size());

               return message::encode(packet, command);
            }
         } // namespace iso14443_type_b

         namespace iso15693
         {
            bool transfer_cmd(data_type & packet, const data_type::value_type & device_addr, const data_type & cmd)
            {
               command::type command(device_addr);
               command.id_ = command::id::ISO15693_Transfer_Command;

               command.data_ = cmd;
               command.data_.push_front(cmd.size());

               return message::encode(packet, command);
            }
         } // namespace iso15693
      } // namespace command

      namespace reply
      {
         bool decode(const data_type & packet, reply::type & reply)
         {
            return message::decode(packet, reply);
         }
      } // namespace repy
   } // mamespace message
} // namespace RDM

//std::ostream & operator<<(std::ostream & os, const rdm::message::reply::status & status)
//{
//   os << rdm::message::reply::status_to_str(status);
//   return os;
//}

//std::stringstream:: & operator<<(std::stringstream & os, const rdm::message::reply::status & status)
//{
//   os << rdm::message::reply::status_to_str(status);
//   return os.rd;
//}

//boost::basic_wrap_stringstream & operator<<(boost::basic_wrap_stringstream & os, const rdm::message::reply::status & status)
//{
//   os << rdm::message::reply::status_to_str(status);
//   return os;
//}

//std::stringstream ss;
//ss << reply.sernum();

std::ostream & operator<<(std::ostream & os, const rdm::message::data_type & rhs)
{
//   std::stringstream ss;
//   std::copy(rhs.begin(), rhs.end(), std::ostream_iterator<uint8_t>(ss));
//   BOOST_LOG_TRIVIAL(debug)<< "<< " << ss.rdbuf() << std::endl;

   std::copy(rhs.begin(), rhs.end(), std::ostream_iterator<rdm::message::data_type::value_type>(os));
   return os;
}

std::istream & operator>>(std::istream & os, rdm::message::data_type & rhs)
{
   std::stringstream ss;

   rdm::message::data_type::value_type item;
   while (os >> item)
   {
      rhs.push_back(item);
      ss << item;
   }

   BOOST_LOG_TRIVIAL(debug)<< ">> " << std::hex << ss.rdbuf() << std::endl;

   return os;
}
