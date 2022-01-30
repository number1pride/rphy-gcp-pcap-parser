extern crate nom;

use pcap_parser::data::{get_packetdata, PacketData};
use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::{LegacyPcapReader, Linktype, PcapBlockOwned, PcapError};

// use std::net::{Ipv4Addr, Ipv6Addr};
use std::fmt;
use std::net::IpAddr;
use std::{fs::File, path::Path};

use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;

use nom::number::streaming::{be_u16, be_u32, be_u8};
use nom::IResult;

// use nom::number::streaming::{be_u16, be_u8};

use crate::parsers::rcp_parser::parse_rcp;

const SNAP_LEN: usize = 65536;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct GcpHeader {
    // GCP Header for TCP
    pub transaction_identifier: u16,
    pub protocol_identifier: u16,
    pub length: u16,
    pub unit_identifier: u8,

    // GCP Message header
    pub message_id: MessageId,
    pub message_length: u16,
}
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct MessageId(pub u8);

#[allow(non_upper_case_globals)]
impl MessageId {
    //
    pub const Req_Notify: MessageId = MessageId(2);
    pub const Rsp_Notify: MessageId = MessageId(3);
    pub const Req_DM: MessageId = MessageId(4);
    pub const Rsp_DM: MessageId = MessageId(5);
    pub const Req_EDS: MessageId = MessageId(6);
    pub const Rsp_EDS: MessageId = MessageId(7);
    pub const Req_EDR: MessageId = MessageId(16);
    pub const Rsp_EDR: MessageId = MessageId(17);
    pub const Req_MWR: MessageId = MessageId(18);
    pub const Rsp_MWR: MessageId = MessageId(19);
    pub const Rsp_Notify_Error: MessageId = MessageId(131);
    pub const Rsp_DM_Error: MessageId = MessageId(133);
    pub const Rsp_EDS_Error: MessageId = MessageId(135);
    pub const Rsp_EDR_Error: MessageId = MessageId(145);
    pub const Rsp_MWR_Error: MessageId = MessageId(147);
}

impl fmt::Debug for MessageId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.0 {
            2 => f.write_str("(2) RequestNotify"),
            3 => f.write_str("(3) ResponseNotify"),
            4 => f.write_str("(4) RequestDeviceManagement"),
            5 => f.write_str("(5) ResponseDeviceManagement"),
            6 => f.write_str("(6) RequestExchangeDataStructures"),
            7 => f.write_str("(7) ResponseExchangeDataStructures"),
            16 => f.write_str("(16) RequestExchangeDataRegister"),
            17 => f.write_str("(17) ResponseExchangeDataRegister"),
            18 => f.write_str("(18) RequestMaskWriteRegister"),
            19 => f.write_str("(19) ResponseMaskWriteRegister"),
            131 => f.write_str("(131) RequestNotifyError"),
            133 => f.write_str("(133) ResponseDeviceManagementError"),
            135 => f.write_str("(135) ResponseExchangeDataStructuresError"),
            145 => f.write_str("(145) ResponseExchangeDataRegisterError"),
            147 => f.write_str("(147) ResponseMaskWriteRegisterError"),
            n => f.debug_tuple("MessageID").field(&n).finish(),
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Status(pub u8);

// #[allow(non_upper_case_globals)]
// impl Status {
//     pub const null_default: Status = Status(0);
//     pub const hardReset: Status = Status(1);
//     pub const softReset: Status = Status(2);
//     pub const nvReset: Status = Status(3);
//     pub const factoryReset: Status = Status(4);
//     // pub const Reserved: Status = Status([5..=255]);
// }
impl fmt::Debug for Status {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.0 {
            0 => f.write_str("0 - Nul (default)"),
            1 => f.write_str("1 - hardReset"),
            2 => f.write_str("2 - softReset"),
            3 => f.write_str("3 - nvReset"),
            4 => f.write_str("4 - factoryReset"),
            (5..=255) => f.write_str("Reserved"),
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ReturnCode(pub u8);

impl fmt::Display for ReturnCode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.0 {
            0 => f.write_str("0 MESSAGE SUCCESSFUL"),
            1 => f.write_str("1 UNSUPPORTED MESSAGE"),
            2 => f.write_str("2 ILLEGAL MESSAGE LENGTH"),
            3 => f.write_str("3 ILLEGAL TRANSACTION ID"),
            4 => f.write_str("4 ILLEGAL MODE"),
            5 => f.write_str("5 ILLEGAL PORT"),
            6 => f.write_str("6 ILLEGAL CHANNEL"),
            7 => f.write_str("7 ILLEGAL COMMAND"),
            8 => f.write_str("8 ILLEGAL VENDOR ID"),
            9 => f.write_str("9 ILLEGAL VENDOR INDEX"),
            10 => f.write_str("10 ILLEGAL ADDRESS"),
            11 => f.write_str("11 ILLEGAL DATA VALUE"),
            12 => f.write_str("12 MESSAGE FAILURE"),
            (13..=127) => f.write_str("Reserved"),
            (128..=254) => f.write_str("128-254 User Defined Codes"),
            255 => f.write_str("255 SLAVE DEVICE FAILURE"),
        }
    }
}

fn header(input: &[u8]) -> IResult<&[u8], GcpHeader> {
    // Parse the header
    let (i, transaction_identifier) = be_u16(input)?;
    let (i, protocol_identifier) = be_u16(i)?;
    let (i, length) = be_u16(i)?;
    let (i, unit_identifier) = be_u8(i)?;
    let (i, msg) = be_u8(i)?;
    let (i, message_length) = be_u16(i)?;

    let header = GcpHeader {
        transaction_identifier,
        protocol_identifier,
        length,
        unit_identifier,
        message_id: MessageId(msg),
        message_length,
    };
    Ok((i, header))
}
pub fn parser(filename: &str) {
    let path = Path::new(filename);
    let pfilename = File::open(path);

    // Handles File IO
    match pfilename {
        // Ok(_) => println!("Hey lets run this mother"),
        Ok(_) => pcap_parser(pfilename.unwrap()),
        Err(e) => eprintln!("error: opening pcap file: '{}'. {}", path.display(), e),
    };
}

fn pcap_parser(pcap_filename: File) {
    let mut num_blocks = 0;
    let mut reader = LegacyPcapReader::new(SNAP_LEN, pcap_filename).expect("LegacyPcapReader");

    loop {
        match reader.next() {
            // NOTE: block counter num_block counts pcap file header
            Ok((offset, block)) => {
                // num_blocks += 1;
                let packetdata = match block {
                    //
                    PcapBlockOwned::LegacyHeader(hdr) => {
                        println!("{}", "*".repeat(50));
                        println!("* PCAP File header:");
                        println!("* Magic Number: {}", hdr.magic_number);
                        println!("* Version: {}.{}", hdr.version_major, hdr.version_minor);
                        println!("* Time Zone: {}", hdr.thiszone);
                        println!("* Time Stamp Accuracy: {}", hdr.sigfigs);
                        println!("* Max len capture packet size: {}", hdr.snaplen);
                        println!("* Linktype {}", hdr.network);
                        println!("{}", "*".repeat(50));
                        reader.consume(offset);
                        continue;
                    }
                    PcapBlockOwned::Legacy(b) => {
                        //
                        num_blocks += 1;
                        print!("Frame: {}, ", num_blocks);
                        print!("Arrival: {}.{}, ", b.ts_sec, b.ts_usec);
                        // println!(", Data: {:X?}", &b.data);
                        let blem = b.caplen as usize;
                        get_packetdata(b.data, Linktype::ETHERNET, blem)
                            .expect("Error parsing this packet")
                    }
                    PcapBlockOwned::NG(_) => unreachable!(),
                };

                let data = match packetdata {
                    PacketData::L2(data) => &data[14..],
                    PacketData::L3(_, data) => data,
                    _ => panic!("Unsupported packet data type"),
                };
                decode_packet_data(data);
                reader.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete) => {
                reader.refill().unwrap();
            }
            Err(e) => panic!("error while reading: {:?}", e),
        }
    }
    // println!("num_blocks: {}", num_blocks);
}

fn decode_packet_data(data: &[u8]) {
    if data.is_empty() {
        return;
    }
    // check L3
    match data[0] & 0xf0 {
        // IPv4
        // 0x40 => {ipv4}
        // IPv6
        0x60 => {
            //
            let ipv6 = &Ipv6Packet::new(data).unwrap();

            // println!("next level proto: {:?}", ipv6.get_next_header());
            let src = IpAddr::V6(ipv6.get_source());
            let dst = IpAddr::V6(ipv6.get_destination());
            print!("sIP: {}, dIP: {}, ", src, dst);

            match ipv6.get_next_header() {
                IpNextHeaderProtocols::Tcp => {
                    if let Some(tcp) = TcpPacket::new(ipv6.payload()) {
                        //parse tcp
                        println!(
                            "sPort: {}, sPort: {}, Size: {}",
                            tcp.get_source(),
                            tcp.get_destination(),
                            tcp.payload().len(),
                        );

                        let (i, hdr) = header(tcp.payload()).unwrap();
                        println!("{}{:?}", " ".repeat(2), hdr);

                        let (_data, _is_done) = message_decoder(i, hdr.message_id).unwrap();
                    }
                }
                IpNextHeaderProtocols::Udp => {
                    println!("UDP is currently not supported");
                }
                _ => (),
            }
        }
        _ => {
            println!("Unknown layer 3 protocol");
        }
    }
}

fn message_decoder(input: &[u8], msg_type: MessageId) -> IResult<&[u8], bool> {
    //
    let mut ret = false;
    let (i, transaction_id) = be_u16(input)?;
    let margin = 4;

    match msg_type {
        //
        MessageId::Req_Notify => {
            //decoders
            let (i, mode) = be_u8(i)?;
            let (i, status) = be_u8(i)?;
            let (i, event_code) = be_u32(i)?;
            //prints
            println!("{}(2) Request Notify:", " ".repeat(margin));
            println!(
                "{}Transaction ID: {}",
                " ".repeat(margin + 4),
                transaction_id
            );

            // TODO - Do this with an impl instead
            let bit7 = (mode & 0b10000000) >> 7;
            let bit6 = (mode & 0b01000000) >> 6;

            let mut bstr = "".to_string();
            if bit7 == 1 {
                bstr.push_str("bit 7=1 : Suppress Normal response");
            } else {
                bstr.push_str("bit 7=0 : Send normal response");
            }

            if bit6 == 1 {
                bstr.push_str(", bit 6=1 : Event data is raw");
            } else {
                bstr.push_str(", bit 6=0 : Event data is text");
            }
            println!("{}Mode: {:b} ({})", " ".repeat(margin + 4), mode, bstr);

            println!("{}Status: {:?}", " ".repeat(margin + 4), Status(status));
            println!("{}Event Code: {:#08X}", " ".repeat(margin + 4), event_code);

            //decode rcp
            let (_rem, _is_done) = parse_rcp(i, margin + 4).unwrap();
        }
        MessageId::Rsp_Notify => {
            println!("{}(3) Response Notify:", " ".repeat(margin));
            let (i, mode) = be_u8(i)?;
            let (_i, event_code) = be_u32(i)?;

            println!(
                "{}Transaction ID: {}",
                " ".repeat(margin + 4),
                transaction_id
            );
            println!("{}Mode: {}", " ".repeat(margin + 4), mode);
            println!("{}Event Code: {:#08X}", " ".repeat(margin + 4), event_code);
        }
        MessageId::Rsp_Notify_Error => {
            let (_i, return_code) = be_u8(input)?;
            println!("{}(131) Response Notify Error:", " ".repeat(margin));
            println!(
                "{}Return Code: {}",
                " ".repeat(margin + 4),
                ReturnCode(return_code)
            );
        }
        MessageId::Req_DM => {
            let (i, mode) = be_u8(i)?;
            let (i, port) = be_u16(i)?;
            let (i, channel) = be_u16(i)?;
            let (_i, command) = be_u8(i)?;

            let bit_7 = (mode & 0b10000000) >> 7;
            let mut mode_bit7 = "".to_string();

            if bit_7 == 0 {
                mode_bit7.push_str("bit7=0: 0 - Send normal response")
            } else {
                mode_bit7.push_str("bit7=1: 1 - Suppress normal response")
            }

            println!("{}(4) Request (DM) Device Management:", " ".repeat(margin));
            println!(
                "{}Transaction ID: {}",
                " ".repeat(margin + 4),
                transaction_id
            );
            println!("{}Mode: {:b} ({})", " ".repeat(margin + 4), mode, mode_bit7);
            println!("{}Port: {:#06X}", " ".repeat(margin + 4), port);
            println!("{}Channel: {:#06X}", " ".repeat(margin + 4), channel);
            if command == 0 {
                println!(
                    "{}Command: {} - Null (default)",
                    " ".repeat(margin + 4),
                    channel
                );
            } else {
                println!("{}Command: (Reserved)", " ".repeat(margin + 4));
            }
        }
        MessageId::Rsp_DM => {
            let (i, mode) = be_u8(i)?;
            let (_i, return_code) = be_u8(i)?;
            println!("{}(5) Response (DM) Device Management:", " ".repeat(margin));
            println!(
                "{}Transaction ID: {:?}",
                " ".repeat(margin + 4),
                transaction_id
            );
            println!("{}Mode: {}", " ".repeat(margin + 4), mode);
            println!(
                "{}Return Code: {}",
                " ".repeat(margin + 4),
                ReturnCode(return_code)
            );
        }
        MessageId::Rsp_DM_Error => {
            let (_i, return_code) = be_u8(i)?;

            println!(
                "{}(133) Response (DM) Device Management Error:",
                " ".repeat(margin)
            );
            println!(
                "{}Transaction ID: {:?}",
                " ".repeat(margin + 4),
                transaction_id
            );
            println!(
                "{}Return Code: {}",
                " ".repeat(margin + 4),
                ReturnCode(return_code)
            );
        }
        MessageId::Req_EDS => {
            //decoders
            let (i, mode) = be_u8(i)?;
            let (i, port) = be_u16(i)?;
            let (i, channel) = be_u16(i)?;
            let (i, vendor_id) = be_u32(i)?;
            let (i, vendor_index) = be_u8(i)?;

            //prints
            println!(
                "{}(6) Request (EDS) Exchange Data Structures:",
                " ".repeat(margin)
            );
            println!(
                "{}Transaction ID: {}",
                " ".repeat(margin + 4),
                transaction_id
            );
            println!("{}Mode: {:#04X}", " ".repeat(margin + 4), mode);
            println!("{}Port: {:#06X}", " ".repeat(margin + 4), port);
            println!("{}Channel: {:#06X}", " ".repeat(margin + 4), channel);
            println!("{}Vendor ID: {}", " ".repeat(margin + 4), vendor_id);
            println!("{}Vendor Index: {}", " ".repeat(margin + 4), vendor_index);

            //decode rcp
            let (_rem, _is_done) = parse_rcp(i, margin + 4).unwrap();
        }
        MessageId::Rsp_EDS => {
            let (i, mode) = be_u8(i)?;
            let (i, port) = be_u16(i)?;
            let (i, channel) = be_u16(i)?;
            let (i, vendor_id) = be_u32(i)?;
            let (i, vendor_index) = be_u8(i)?;

            println!(
                "{}(7) Response (EDS) Exchange Data Structures:",
                " ".repeat(margin)
            );
            println!(
                "{}Transaction ID: {:?}",
                " ".repeat(margin + 4),
                transaction_id
            );
            println!("{}Mode: {:#04X}", " ".repeat(margin + 4), mode);
            println!("{}Port: {:#06X}", " ".repeat(margin + 4), port);
            println!("{}Channel: {:#06X}", " ".repeat(margin + 4), channel);
            println!("{}Vendor ID: {}", " ".repeat(margin + 4), vendor_id);
            println!("{}Vendor Index: {}", " ".repeat(margin + 4), vendor_index);

            //decode rcp
            let (_rem, _is_done) = parse_rcp(i, margin + 4).unwrap();
        }
        MessageId::Rsp_EDS_Error => {
            println!(
                "{}(135) Response (EDS) Exchange Data Structures Error:",
                " ".repeat(margin)
            );
        }
        MessageId::Req_EDR => {
            println!(
                "{}(16) Request (EDR) Exchange Data Register:",
                " ".repeat(margin)
            );
        }
        MessageId::Rsp_EDR => {
            println!(
                "{}(17) Response (EDR) Exchange Data Register:",
                " ".repeat(margin)
            );
        }
        MessageId::Rsp_EDR_Error => {
            println!(
                "{}(145) Response (EDR) Exchange Data Register Error:",
                " ".repeat(margin)
            );
        }
        MessageId::Req_MWR => {
            println!(
                "{}(18) Request (MWR) Mask Write Register:",
                " ".repeat(margin)
            );
        }
        MessageId::Rsp_MWR => {
            println!(
                "{}(19) Response (MWR) Mask Write Register:",
                " ".repeat(margin)
            );
        }
        MessageId::Rsp_MWR_Error => {
            println!(
                "{}(147) Response (MWR) Mask Write Register Error:",
                " ".repeat(margin)
            );
        }
        _ => {
            println!("Unsupported GCP message Type")
        }
    }

    // check the size of data to see if it consumed everything
    // if i.len() == 0 {
    //     ret = true;
    // }

    if i.is_empty() {
        ret = true
    }

    Ok((i, ret))
}
