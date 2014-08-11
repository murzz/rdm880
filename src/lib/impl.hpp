#include <limits>
#include <cstdint>
#include <sstream>
#include <deque>

#include "misc.hpp"
#include "rdm.hpp"

namespace rdm
{
   namespace message
   {
      namespace framing
      {
         namespace value
         {
            static const data_type::value_type STX = 0xAA;
            static const data_type::value_type ETX = 0xBB;
         } // namespace value

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

            static const data_type::size_type reply_rstb_len = 0;
            /// @note specs failing me here, SNR starts from first byte, not second
            //static const data_type::size_type reply_rstb = 1;
            static const data_type::size_type reply_rstb = 0;
         } // namespace offset

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
               data_type::size_type size = std::numeric_limits<data_type::size_type>::max());

         /// checks if frame is sane:
         ///   - minimum size is met
         ///   - STX and ETX are there
         bool is_sane(const data_type & frame);

         /// Extracts BCC byte from packet.
         bool extract_bcc(const data_type & frame, data_type::value_type & bcc);

         /// Frame with STX, BCC and ETX.
         bool encode(data_type & packet);

         /// Verify frame integrity
         ///   - calculate BCC
         ///   - check frame size
         bool verify(const data_type & frame);

         /// Verify frame and remove framing bytes (STX, BCC and ETX)
         bool decode(data_type & frame);

      } // namespace framing

      namespace command
      {
         enum class id
         {
            /// not part of protocol, should mark empty command
            Empty = 0x00,

            // ISO14443-B Command (0x09-0x0E)

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

            // ISO15693 Commands (0x10~0x1D)

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

            // Mifare Application Commands (0x20~0x2F)

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

            // System commands (0x80~0x8F)

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

            type(data_type::value_type device_addr = message::default_device_addr);
            virtual ~type();
         };

         /// Encode command to packet.
         bool encode(data_type & packet, const command::type & command);

         /// Decode packet to reply.
         bool decode(const data_type & packet, reply::type & reply);

      } // namespace command
   } // mamespace message
} // namespace RDM

