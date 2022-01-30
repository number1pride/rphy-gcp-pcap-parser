extern crate nom;

use nom::number::complete::be_u16;
pub use nom::IResult;
use nom_derive::{NomBE, Parse};
use rusticata_macros::newtype_enum;

use crate::parsers::tlv_parser::parse_rphy_tlvs;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default, NomBE)]
pub struct RcpMessageType(pub u8);

newtype_enum! {
    impl display RcpMessageType {
        IRA = 1,
        REX = 2,
        NTF = 3,
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct RcpSequence {
    pub sequence: u8,
    pub sequence_size: u16,
    pub sequence_number: u16,
    pub operation: Operation,
}

//------------------------------
// TLVs Start
#[derive(Debug, Clone, Copy, Eq, PartialEq, Default, NomBE)]
pub struct Operation(pub u8);

newtype_enum! {
    impl display Operation {
        Read = 1,
        Write = 2,
        Delete = 3,
        ReadResponse = 4,
        WriteResponse = 5,
        DeleteResponse = 6,
        AllocateWrite = 7,
        AllocateWriteResponse = 8,
    }
}

pub fn parse_rcp(input: &[u8], margin_base: usize) -> IResult<&[u8], bool> {
    let (i, message_type) = RcpMessageType::parse(input).unwrap();
    let (i, _message_size) = be_u16(i)?; //just jumping bytes, not needed

    // dbg!(message_type);
    match message_type {
        RcpMessageType::IRA => {
            println!(
                "{}IRA: Identification and Resource Advertising",
                " ".repeat(margin_base)
            );
            // decode_rcp_sequences(i).expect("\t Sequence: Unable to decode sequence.");
            parse_rphy_tlvs(i, margin_base + 2);
        }
        RcpMessageType::REX => {
            println!("{}REX: RCP Object Exchange", " ".repeat(margin_base));

            parse_rphy_tlvs(i, margin_base + 2);
        }
        RcpMessageType::NTF => {
            println!("{}NTF: Notification", " ".repeat(margin_base));

            parse_rphy_tlvs(i, margin_base + 2);
        }
        _ => {
            println!("{}Unsupported RCP Message Type", " ".repeat(margin_base));
        }
    }

    Ok((i, true))
}
