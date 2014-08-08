#pragma once

#include <limits>
#include <cstdint>
#include <sstream>
//#include <vector>
#include <deque>
#include "misc.hpp"

#include <boost/log/trivial.hpp>
#include <boost/iostreams/stream.hpp>

namespace rdm
{
namespace message
{
typedef std::deque<std::uint8_t> data_type;
namespace framing
{
namespace value
{
static const data_type::value_type STX = 0xAA;
static const data_type::value_type ETX = 0xBB;
}
namespace offset
{
static const data_type::size_type stx = 0;
static const data_type::size_type device_addr = 1;
static const data_type::size_type data_len = 2;
static const data_type::size_type cmd = 3; // command only
static const data_type::size_type status = 3; // response only
static const data_type::size_type data = 4; // if any
static const data_type::size_type etx_reverse = 0;
static const data_type::size_type bcc_reverse = 1;

static const data_type::size_type status_code = 0;

static const data_type::size_type reply_baudrate = 0;
static const data_type::size_type reply_device_addr = 0;
static const data_type::size_type reply_sernum = 1;
static const data_type::size_type reply_control_buzzer = 0;

static const data_type::size_type reply_mifare_sernum_flag = 0;
static const data_type::size_type reply_mifare_sernum = 1;

static const data_type::size_type reply_atqb_len = 0;
static const data_type::size_type reply_atqb = 1;
}

namespace size
{
static const data_type::size_type stx = sizeof(data_type::value_type);
static const data_type::size_type device_addr = stx;
static const data_type::size_type data_len = stx;
static const data_type::size_type cmd = stx; // command only
static const data_type::size_type status = stx; // response only
static const data_type::size_type bcc = stx;
static const data_type::size_type etx = stx;

static const data_type::size_type frame_min = stx + device_addr + data_len + cmd + bcc + etx;

/// Quote from specs:
/// If the Data Field of the Command/Reply Message has more then 80 bytes,
/// the reader won’t response and treats this command as an error and wait
/// for another command.
static const data_type::size_type data_field_max = 80;

static const data_type::size_type status_code = 1;

static const data_type::size_type sernum = 8;
static const data_type::size_type version_min = 6;
}

/// Calculates Block Check Character.
data_type::value_type calculate_bcc(const data_type & packet, data_type::size_type start_idx = 0,
      data_type::size_type size = std::numeric_limits<data_type::size_type>::max())
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

/// checks if frame is sane:
///   - minimum size is met
///   - STX and ETX are there
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

/// Extracts BCC byte from packet.
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

/// Frame with STX, BCC and ETX.
bool encode(data_type & packet)
{
   packet.push_back(calculate_bcc(packet));
   packet.push_back(framing::value::ETX);
   packet.push_front(framing::value::STX);
   return true;
}

/// Verify frame integrity
///   - calculate BCC
///   - check frame size
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

/// Verify frame and remove framing bytes (STX, BCC and ETX)
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

/// default device address, @c 0x00 for point-to-point connection (RS-232).
static const data_type::value_type default_device_addr = 0x00;

/// if command failed it will be retried up to max retry count
static const std::size_t max_retry_count = 3;

/// Mifare get serial number command request mode: request idle
static const data_type::value_type mifare_request_idle = 0x26;

/// Mifare get serial number command request mode: request all
static const data_type::value_type mifare_request_all = 0x52;

/// Mifare get serial number command request mode: do not need to execute the halt command
static const data_type::value_type mifare_no_halt = 0x00;

/// Mifare get serial number command request mode: need to execute the halt command
static const data_type::value_type mifare_do_halt = 0x01;

/// Mifare ISO14443_TypeA_Transfer_Command: transfer CRC to the card
static const data_type::value_type mifare_transfer_crc = 0x01;

/// Mifare ISO14443_TypeA_Transfer_Command: do not transfer CRC to the card
static const data_type::value_type mifare_no_transfer_crc = 0x00;

enum class baudrate
{
   baud_9600 = 0x00, baud_19200 = 0x01, baud_38400 = 0x02, baud_57600 = 0x03, baud_115200 = 0x04,
};

namespace command
{

enum class id
{
   /// not part of protocol, should mark empty command
   Empty = 0x00,

   /// ISO14443-B Command (0x09-0x0E)

   ///  ISO14443B REQB Command
   Request_B = 0x09,

   /// ISO14443B Anti-collision
   AnticollB = 0x0A,

   /// ISO14443B ATTRIB Command
   Attrib_B = 0x0B,

   /// Integrate the REQB and ATTRIB Command
   Rst_TypeB = 0x0C,

   /// ISO14443-4 transparent command Type B Card
   ISO14443_TypeB_Transfer_Command = 0x0D,

   /// ISO15693 Commands (0x10~0x1D)

   ///  ISO15693 Inventory Command
   ISO15693_Inventory = 0x10,

   /// ISO15693 Read Command
   ISO15693_Read = 0x11,

   /// ISO15693 Write Command
   ISO15693_Write = 0x12,

   /// ISO15693 Lock_Block Command
   ISO15693_Lockblock = 0x13,

   /// ISO15693 Stay_Quiet Command
   ISO15693_StayQuiet = 0x14,

   /// ISO15693_Select Command
   ISO1569_Select = 0x15,

   /// ISO15693_Reset_To_Ready Command
   ISO15693_Resetready = 0x16,

   /// ISO15693_Write_AFI Command
   ISO15693_Write_Afi = 0x17,

   /// ISO15693_Lock_AFI Command
   ISO15693_Lock_Afi = 0x18,

   /// ISO15693_Write_DSFID Command
   ISO15693_Write_Dsfid = 0x19,

   /// ISO15693_Lock_DSFID Command
   ISO15693_Lock_Dsfid = 0x1A,

   /// ISO15693_Get_System_Information Command
   ISO15693_Get_Information = 0x1B,

   /// ISO15693_Get_Multiple_Block_Security Command
   ISO15693_Get_Multiple_Block_Security = 0x1C,

   ///Using this command may transparent any    command to The Card which command   meet the ISO15693 protocol
   ISO15693_Transfer_Command = 0x1D,

   /// Mifare Application Commands (0x20~0x2F)

   /// The Read command integrates the low level commands (request, anti-collision, select,
   /// authentication, read) to achieve the reading operation with a one-step single command.
   MF_Read = 0x20,

   /// The Write command integrates the low level commands (request, anti-collision, select,
   /// authentication, write) to achieve the writing operation with a one-step single command.
   MF_Write = 0x21,

   /// The Initialization command integrates the low level commands (request, anti-collision,
   /// select, authentication) to achieve the value block initialization with a one-step single command.
   MF_InitVal = 0x22,

   /// The Decrement command integrates the low level commands (request, anti-collision, select,
   /// authentication) to achieve the Decrement with a one-step single command.
   MF_Decrement = 0x23,

   /// The Increment command integrates the low level commands (request, anti-collision, select,
   /// authentication) to achieve the Increment with a one-step single command.
   MF_Increment = 0x24,

   /// The GetSnr command integrates the low level commands (request,anticoll,select) to achieve the
   /// select card with a one-step single command, and output the card’s Snr
   MF_GET_SNR = 0x25,

   /// Using this command you may transparent any command to The Card which these commands meet
   /// the ISO14443-TypeA protocol
   ISO14443_TypeA_Transfer_Command = 0x28,

   /// System commands (0x80~0x8F)

   /// Program the Device Address to the reader (The  range of address is 0~255)
   SetAddress = 0x80,

   /// Set the reader’s communication baud rate(9600~115200)
   SetBaudrate = 0x81,

   /// Set the reader’s Serial Number(The Seial Number is 8 byte)
   SetSerlNum = 0x82,

   /// Get the reader’s Serial Number And Address
   GetSerlNum = 0x83,

   /// Set the Usr Information
   Write_UserInfo = 0x84,

   /// Get the Usr Information
   Read_UserInfo = 0x85,

   /// Get the reader’s firmware version number
   Get_VersionNum = 0x86,

   /// Turn On/Off the LED1
   Control_Led1 = 0x87,

   /// Turn On/Off the LED2
   Control_Led2 = 0x88,

   /// Turn On/Off the Buzzer
   Control_Buzzer = 0x89,
};

struct type
{
   data_type::value_type device_addr_;
   command::id id_;
   data_type data_;
   type(data_type::value_type device_addr = message::default_device_addr) :
         device_addr_(device_addr), id_(command::id::Empty)
   {
   }

   virtual ~type()
   {
   }
};
}

namespace reply
{
enum class status
{
//System Error/Status Codes (0x00-0x0F)
///  Command OK.
   command_ok = 0x00,
/// Command FAILURE
   command_failure = 0x01,
/// SET OK.
   set_ok = 0x80,
/// SET FAILURE
   set_failure = 0x81,
/// Reader reply time out error
   reader_reply_timeout = 0x82,
/// The card do not exist
   card_not_exists = 0x83,
/// The data response from the card is error
   card_response_error = 0x84,
/// The parameter of the command or the Format of the command Error
   unknown_parameter = 0x85,
/// Unknown Internal Error
   internal_error = 0x87,
///Reader received unknown command
   unknown_command = 0x8f,

//ISO14443 Error Codes：
/// Some Error appear in the card InitVal process
   iso14443_init_val_error = 0x8A,
///Get The Wrong Snr during anticollison loop
   iso14443_anticollision_error = 0x8B,
/// The authentication failure
   iso14443_auth_failure = 0x8C,

//ISO15693  Error Codes：
///The Card do not support this command
   iso15693_unsupported_command = 0x90,
/// The Foarmat Of  The Command Erro
   iso15693_format_error = 0x91,
///Do not support Option mode
   iso15693_unsupported_option = 0x92,
///The Block Do Not Exist
   iso15693_block_not_exists = 0x93,
///The Object have been locked
   iso15693_object_locked = 0x94,
///The lock Operation Do Not Success
   iso15693_lock_failed = 0x95,
///The Operation Do Not Success
   iso15693_failed = 0x96,
};

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

struct type
{
   data_type::value_type device_addr_;
   reply::status status_;
   data_type data_;
   type() :
         device_addr_(message::default_device_addr), status_(reply::status::command_failure)
   {
   }

   virtual ~type()
   {
   }

   const data_type::value_type & device_addr() const
   {
      return device_addr_;
   }

   const reply::status & status() const
   {
      return status_;
   }

/// If status is no OK then there might be status code with error description
   const reply::status status_code() const
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

   const data_type & data() const
   {
      return data_;
   }
};

struct with_result: public reply::type
{
   data_type::value_type result()
   {
      return data_.at(framing::offset::reply_control_buzzer);
   }
};

namespace system
{
struct set_address: public reply::type
{
   data_type::value_type new_device_addr()
   {
      return data_.at(framing::offset::reply_device_addr);
   }
};

struct set_baudrate: public reply::type
{
   message::baudrate baudrate()
   {
      return static_cast<message::baudrate>(data_.at(framing::offset::reply_baudrate));
   }
};

struct get_version_num: public reply::type
{
   const data_type & version()
   {
      return data_;
   }
};

struct get_ser_num: public reply::type
{
   data_type::value_type & reported_device_addr()
   {
      return data_.at(framing::offset::reply_device_addr);
   }
   data_type sernum()
   {
      return mid(data_, framing::offset::reply_sernum);
   }
};

struct control_buzzer: public reply::with_result
{
};
}   //namespace system

namespace mifare
{
struct get_ser_num: public reply::type
{
   data_type::value_type & flag()
   {
      return data_.at(framing::offset::reply_mifare_sernum_flag);
   }

   data_type sernum()
   {
      return mid(data_, framing::offset::reply_mifare_sernum);
   }
};
struct transfer_cmd: public reply::type
{
};
} // namespace mifare

namespace iso14443_type_b
{
struct request: public reply::type
{
   data_type atq()
   {
      return mid(data_, framing::offset::reply_atqb);
   }

   data_type::value_type & reported_len()
   {
      return data_.at(framing::offset::reply_atqb_len);
   }

};
struct transfer_cmd: public reply::type
{
};
} // namespace iso14443_type_b

namespace iso15693
{
struct transfer_cmd: public reply::type
{
};
} // namespace iso15693

} // namespace reply

/// Encode command to packet.
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

/// Decode packet to reply.
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

bool set_baudrate(data_type & packet, const data_type::value_type & device_addr, const message::baudrate & value)
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

bool control_led1(data_type & packet, const data_type::value_type & device_addr, data_type::value_type blink_duration,
      data_type::value_type blink_count)
{
   command::type command(device_addr);
   command.id_ = command::id::Control_Led1;
   command.data_.push_back(blink_duration);
   command.data_.push_back(blink_count);

   return message::encode(packet, command);
}

bool control_led2(data_type & packet, const data_type::value_type & device_addr, data_type::value_type blink_duration,
      data_type::value_type blink_count)
{
   command::type command(device_addr);
   command.id_ = command::id::Control_Led2;
   command.data_.push_back(blink_duration);
   command.data_.push_back(blink_count);

   return message::encode(packet, command);
}

bool control_buzzer(data_type & packet, const data_type::value_type & device_addr, data_type::value_type buzz_duration,
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
      data_type::value_type request_mode = message::mifare_request_idle,
      data_type::value_type execute_halt = message::mifare_no_halt)
{
   command::type command(device_addr);
   command.id_ = command::id::MF_GET_SNR;
   command.data_.push_back(request_mode);
   command.data_.push_back(execute_halt);

   return message::encode(packet, command);
}

/// This command is using for transparent any command to The Card which these
/// commands meet the ISO14443-Typea protocol
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
bool request(data_type & packet, const data_type::value_type & device_addr, const data_type::value_type & AFI,
      const data_type::value_type & slot_num)
{
   command::type command(device_addr);
   command.id_ = command::id::Request_B;

   // values could be skipped from package, I guess some defaults are assumed by RDM
   command.data_.push_back(AFI);
   command.data_.push_back(slot_num);

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
/// This command is using for transparent any command to The Card which these commands meet the ISO15693 protocol.
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
