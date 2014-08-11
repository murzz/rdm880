#pragma once

#include <cstdint>
#include <deque>

namespace rdm
{
   namespace message
   {
      typedef std::deque<std::uint8_t> data_type;

      enum class baudrate
      {
         baud_9600 = 0x00, baud_19200 = 0x01, baud_38400 = 0x02, baud_57600 = 0x03, baud_115200 = 0x04,
      };

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

            /// The Format Of The Command Error
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

         std::string status_to_str(const rdm::message::reply::status & status);

         struct type
         {
            data_type::value_type device_addr_;
            reply::status status_;
            data_type data_;

            type();
            virtual ~type();
            const data_type::value_type & device_addr() const;
            const reply::status & status() const;

            /// If status is not OK then there might be status code with detailed error
            reply::status status_code() const;
            const data_type & data() const;
         };

         struct with_result: public reply::type
         {
            data_type::value_type result();
         };

         namespace system
         {
            struct set_address: public reply::type
            {
               data_type::value_type new_device_addr();
            };

            struct set_baudrate: public reply::type
            {
               message::baudrate baudrate();
            };

            struct get_version_num: public reply::type
            {
               const data_type & version();
            };

            struct get_ser_num: public reply::type
            {
               data_type::value_type & reported_device_addr();
               data_type sernum();
            };

            struct control_buzzer: public reply::with_result
            {
            };
         }   //namespace system

         namespace mifare
         {
            struct get_ser_num: public reply::type
            {
               data_type::value_type & flag();

               data_type sernum();
            };
            struct transfer_cmd: public reply::type
            {
            };
         } // namespace mifare

         namespace iso14443_type_b
         {
            struct request: public reply::type
            {
               data_type atq();

               const data_type::value_type & reported_len();
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

      namespace command
      {
         namespace system
         {
            bool set_address(data_type & packet, const data_type::value_type & device_addr,
                  const data_type::value_type & new_device_addr);

            bool set_baudrate(data_type & packet, const data_type::value_type & device_addr,
                  const rdm::message::baudrate & value);

            bool get_ser_num(data_type & packet, const data_type::value_type & device_addr);

            bool get_version_num(data_type & packet, const data_type::value_type & device_addr);

            bool control_led1(data_type & packet, const data_type::value_type & device_addr,
                  data_type::value_type blink_duration,
                  data_type::value_type blink_count);

            bool control_led2(data_type & packet, const data_type::value_type & device_addr,
                  data_type::value_type blink_duration,
                  data_type::value_type blink_count);

            bool control_buzzer(data_type & packet, const data_type::value_type & device_addr,
                  data_type::value_type buzz_duration,
                  data_type::value_type buzz_count);
         } // namespace system
         namespace mifare
         {
            bool get_ser_num(data_type & packet, const data_type::value_type & device_addr,
                  data_type::value_type request_mode = rdm::message::mifare_request_idle,
                  data_type::value_type execute_halt = rdm::message::mifare_no_halt);

/// This command is using for transparent any command to The Card which these
/// commands meet the ISO14443-Typea protocol
            bool transfer_cmd(data_type & packet, const data_type::value_type & device_addr,
                  const data_type::value_type & crc_flag, const data_type & cmd);
         } // namespace mifare
         namespace iso14443_type_b
         {
            bool request(data_type & packet, const data_type::value_type & device_addr,
                  const data_type::value_type & AFI,
                  const data_type::value_type & slot_num);
            bool transfer_cmd(data_type & packet, const data_type::value_type & device_addr, const data_type & cmd);
         } // namespace iso14443_type_b
         namespace iso15693
         {
/// This command is using for transparent any command to The Card which these commands meet the ISO15693 protocol.
            bool transfer_cmd(data_type & packet, const data_type::value_type & device_addr, const data_type & cmd);
         } // namespace iso15693
      } // namespace command

      namespace reply
      {
         bool decode(const data_type & packet, reply::type & reply);
      } // namespace repy
   } // mamespace message
} // namespace RDM

std::ostream & operator<<(std::ostream & os, const rdm::message::data_type & rhs);
std::istream & operator>>(std::istream & os, rdm::message::data_type & rhs);
