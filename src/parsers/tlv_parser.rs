extern crate nom;

use eui48::MacAddress;
use hex_fmt::HexFmt;
use nom::bytes::complete::take;
use nom::multi::many1;
use nom::number::complete::{be_u16, be_u8};
use nom::IResult;
use std::borrow::Cow;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str;
// use byteorder::{BigEndian, ByteOrder};
// use pnet::packet::ip::IpNextHeaderProtocols::Reserved;
// use nom_derive::{NomBE, Parse};
// use rusticata_macros::newtype_enum;

const SYM_MICRO: [u8; 2] = [0xC2, 0xB5]; //UTF-8 Micro symbol

#[derive(Debug, PartialEq)]
pub struct RphyTlv<'a> {
    pub typ: u8,
    pub len: u16,
    pub val: &'a [u8],
}
#[derive(Debug)]
pub struct Operation(pub u8);
impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            1 => write!(f, "(1) Read"),
            2 => write!(f, "(2) Write"),
            3 => write!(f, "(3) Delete"),
            4 => write!(f, "(4) ReadResponse"),
            5 => write!(f, "(5) WriteResponse"),
            6 => write!(f, "(6) DeleteResponse"),
            7 => write!(f, "(7) AllocateWrite"),
            8 => write!(f, "(8) AllocateWriteResponse"),
            n => f.debug_tuple("Operation").field(&n).finish(),
        }
    }
}

#[derive(Debug)]
struct AuxCoreGcpConnectionStatus(u8);
impl fmt::Display for AuxCoreGcpConnectionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            0 => write!(f, "(0) - Not connected"),
            1 => write!(f, "(1) - Connected"),
            2 => write!(f, "(2) - Reconnecting"),
            3 => write!(f, "(3) - Handover to Backup Core initiated by RPD "),
            4 => write!(f, "(4) - Backup Core active"),
            5 => write!(f, "(5) - Backup Core rejected handover "),
            6 => write!(f, "(6) - No Backup Core found"),
            7 => write!(f, "(7) - Handover to Backup Core failed"),
            8 => write!(f, "(8) - Handover to Backup Core initiated by Active Core"),
            n => f
                .debug_tuple("AuxCoreGcpConnectionStatus")
                .field(&n)
                .finish(),
        }
    }
}

#[derive(Debug)]
struct RfChannelType(u8);
impl fmt::Display for RfChannelType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            1 => write!(f, "(1) - DsScQam."),
            2 => write!(f, "(2) - DsOfdm."),
            3 => write!(f, "(3) - Ndf"),
            4 => write!(f, "(4) - DsScte55d1."),
            5 => write!(f, "(5) - UsAtdma."),
            6 => write!(f, "(6) - UsOfdma."),
            7 => write!(f, "(7) - reserved"),
            8 => write!(f, "(8) - Ndr channel"),
            9 => write!(f, "(9) - UsScte55d1."),
            10 => write!(f, "(10) - DsScte55d2."),
            11 => write!(f, "(11) - UsScte55d2."),
            n => f.debug_tuple("RfChannelType").field(&n).finish(),
        }
    }
}

#[derive(Debug)]
struct ResponseCode(u8);
impl fmt::Display for ResponseCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            0 => write!(f, "(0) - NoError"),
            1 => write!(f, "(1) - GeneralError"),
            2 => write!(f, "(2) - ResponseTooBig"),
            3 => write!(f, "(3) - AttributeNotFound"),
            4 => write!(f, "(4) - BadIndex"),
            5 => write!(f, "(5) - WriteToReadOnly"),
            6 => write!(f, "(6) - InconsistentValue"),
            7 => write!(f, "(7) - WrongLength"),
            8 => write!(f, "(8) - WrongValue"),
            9 => write!(f, "(9) - ResourceUnavailable"),
            10 => write!(f, "(10) - AuthorizationFailure"),
            11 => write!(f, "(11) - AttributeMissing"),
            12 => write!(f, "(12) - AllocationFailure"),
            13 => write!(f, "(13) - AllocationNoOwner"),
            14 => write!(f, "(14) - ErrorProcessingUCD"),
            15 => write!(f, "(15) - ErrorProcessingOCD"),
            16 => write!(f, "(16) - ErrorProcessingDPD"),
            17 => write!(f, "(17) - SessionIdInUse"),
            18 => write!(f, "(18) - DoesNotExist"),
            n => f.debug_tuple("ResponseCode").field(&n).finish(),
        }
    }
}

#[derive(Debug)]
struct EvPriority(u8);
impl fmt::Display for EvPriority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            1 => write!(f, "(1) - emergency"),
            2 => write!(f, "(2) - alert"),
            3 => write!(f, "(3) - critical"),
            4 => write!(f, "(4) - error"),
            5 => write!(f, "(5) - warning"),
            6 => write!(f, "(6) - notice"),
            7 => write!(f, "(7) - information"),
            8 => write!(f, "(8) - debug"),
            n => f.debug_tuple("EvPriority").field(&n).finish(),
        }
    }
}

#[derive(Debug)]
struct EvThrottleAdminStatus(u8);
impl fmt::Display for EvThrottleAdminStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            1 => write!(f, "(1) - unconstrained"),
            2 => write!(f, "(2) - maintainBelowThreshold"),
            3 => write!(f, "(3) - stopAtThreshold"),
            4 => write!(f, "(4) - inhibited"),
            n => f.debug_tuple("EvThrottleAdminStatus").field(&n).finish(),
        }
    }
}

#[derive(Debug)]
struct GcpRecoveryAction(u8);
impl fmt::Display for GcpRecoveryAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            1 => write!(f, "(1) - GcpWaitForActionFromCore."),
            2 => write!(f, "(2) - GcpReconnectToTheSameCore."),
            3 => write!(f, "(3) - GcpHandoverToBackupCore."),
            4 => write!(f, "(4) - WaitAndReboot."),
            5 => write!(f, "(5) - GcpHandoverToBackupCoreAfterReconnectFail."),
            n => f.debug_tuple("GcpRecoveryAction").field(&n).finish(),
        }
    }
}

#[derive(Debug)]
struct CoreMode(u8);

impl fmt::Display for CoreMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            1 => write!(f, "(1) - Active"),
            2 => write!(f, "(2) - Backup"),
            3 => write!(f, "(3) - NotActing"),
            4 => write!(f, "(4) - DecisionPending "),
            5 => write!(f, "(5) - OutOfService"),
            6 => write!(f, "(6) - ContactPending "),
            7 => write!(f, "(7) - Deprecated"),
            8 => write!(f, "(8) - Redirect"),
            n => f.debug_tuple("CoreMode").field(&n).finish(),
        }
    }
}

#[derive(Debug)]
struct AdminStateType(u8);
impl fmt::Display for AdminStateType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            1 => write!(f, "(1) - other"),
            2 => write!(f, "(2) - up"),
            3 => write!(f, "(3) - down"),
            4 => write!(f, "(4) - testing "),
            n => f.debug_tuple("AdminStateType").field(&n).finish(),
        }
    }
}

#[derive(Debug)]
struct OperationalMode(u8);
impl fmt::Display for OperationalMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            1 => write!(f, "(1) - Other"),
            2 => write!(f, "(2) - Channel operates as DOCSIS channel."),
            3 => write!(f, "(3) - Channel operates as a synchronous MPEG video channel. "),
            4 => write!(f, "(4) - Channel operates as an asynchronous MPEG video channel."),
            5 => write!(f, "(5) - Channel operates as CW carrier; that is as a Pilot Tone or an Alignment Carrier."),
            n => f.debug_tuple("OperationalMode").field(&n).finish(),
        }
    }
}

#[derive(Debug)]
struct InterleaverDepth(u8);
impl fmt::Display for InterleaverDepth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            1 => write!(f, "(1) - unknown"),
            2 => write!(f, "(2) - other"),
            3 => write!(f, "(3) - taps8Increment16"),
            4 => write!(f, "(4) - taps16Increment8"),
            5 => write!(f, "(5) - taps32Increment4"),
            6 => write!(f, "(6) - taps64Increment2"),
            7 => write!(f, "(7) - taps128Increment1"),
            8 => write!(f, "(8) - taps12increment17"),
            9 => write!(f, "(9) - taps128Increment2"),
            10 => write!(f, "(10) - taps128Increment3"),
            11 => write!(f, "(11) - taps128Increment4"),
            12 => write!(f, "(12) - taps128Increment5"),
            13 => write!(f, "(13) - taps128Increment6"),
            14 => write!(f, "(14) - taps128Increment7"),
            15 => write!(f, "(15) - taps128Increment8"),
            n => f.debug_tuple("InterleaverDepth").field(&n).finish(),
        }
    }
}

struct RfPortType(u8);
impl fmt::Display for RfPortType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            1 => write!(f, "(1) - DsRfPort"),
            2 => write!(f, "(2) - UsRfPort"),

            n => f.debug_tuple("RfPortType").field(&n).finish(),
        }
    }
}

struct DsModulationType(u8);
impl fmt::Display for DsModulationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            1 => write!(f, "(1) - Unknown"),
            2 => write!(f, "(2) - Other"),
            3 => write!(f, "(3) - Qam64"),
            4 => write!(f, "(4) - Qam256"),
            n => f.debug_tuple("DsModulationType").field(&n).finish(),
        }
    }
}

struct DsInterleaverType(u8);
impl fmt::Display for DsInterleaverType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            1 => write!(f, "(1) - Unknown"),
            2 => write!(f, "(2) - Other"),
            3 => write!(f, "(3) - annex A"),
            4 => write!(f, "(4) - annex B"),
            5 => write!(f, "(5) - annex C"),
            n => f.debug_tuple("DsInterleaverType").field(&n).finish(),
        }
    }
}

struct CyclicPrefix(u8);
impl fmt::Display for CyclicPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            1 => write!(f, "(1) - 192"),
            2 => write!(f, "(2) - 256"),
            3 => write!(f, "(3) - 512"),
            4 => write!(f, "(4) - 768"),
            5 => write!(f, "(5) - 1024"),
            n => f.debug_tuple("CyclicPrefix").field(&n).finish(),
        }
    }
}

struct RollOffPeriodType(u8);
impl fmt::Display for RollOffPeriodType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            1 => write!(f, "(1) - 0"),
            2 => write!(f, "(2) - 64"),
            3 => write!(f, "(3) - 128"),
            4 => write!(f, "(4) - 192"),
            5 => write!(f, "(5) - 256"),
            n => f.debug_tuple("RollOffPeriodType").field(&n).finish(),
        }
    }
}

struct SubcarrierUsage(u8);
impl fmt::Display for SubcarrierUsage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            1 => write!(f, "(1) - Other"),
            2 => write!(f, "(2) - Data"),
            3 => write!(f, "(3) - Plc"),
            4 => write!(f, "(4) - Continuous Pilot"),
            5 => write!(f, "(5) - Excluded"),
            6 => write!(f, "(5) - Unused"),
            n => f.debug_tuple("SubcarrierUsage").field(&n).finish(),
        }
    }
}

struct DsOfdmModulationType(u8);
impl fmt::Display for DsOfdmModulationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            1 => write!(f, "(1) - Other"),
            2 => write!(f, "(2) - zeroValued"),
            3 => write!(f, "(3) - qpsk"),
            4 => write!(f, "(4) - qam16"),
            5 => write!(f, "(5) - qam64"),
            6 => write!(f, "(6) - qam128"),
            7 => write!(f, "(7) - qam256"),
            8 => write!(f, "(8) - qam512"),
            9 => write!(f, "(9) - qam1024"),
            10 => write!(f, "(10) - qam2048"),
            11 => write!(f, "(11) - qam4096"),
            12 => write!(f, "(12) - qam8192"),
            13 => write!(f, "(13) - qam16384"),
            n => f.debug_tuple("DsOfdmModulationType").field(&n).finish(),
        }
    }
}

struct UpstreamChannelType(u8);
impl fmt::Display for UpstreamChannelType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            0 => write!(f, "(0) - Unknown(0)"),
            1 => write!(f, "(1) - TDMA"),
            2 => write!(f, "(2) - ATDMA"),
            3 => write!(f, "(3) - Reserved"),
            4 => write!(f, "(4) - TDMAandATDMA"),
            n => f.debug_tuple("UpstreamChannelType").field(&n).finish(),
        }
    }
}

struct UpstreamModulationType(u8);
impl fmt::Display for UpstreamModulationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            0 => write!(f, "(0) - other"),
            1 => write!(f, "(1) - QPSK"),
            2 => write!(f, "(2) - QAM16"),
            3 => write!(f, "(3) - QAM32"),
            4 => write!(f, "(4) - QAM64"),
            5 => write!(f, "(5) - QAM128"),
            n => f.debug_tuple("UpstreamModulationType").field(&n).finish(),
        }
    }
}

struct QueryScQamModulationType(u8);
impl fmt::Display for QueryScQamModulationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            1 => write!(f, "(1) - other"),
            2 => write!(f, "(2) - QPSK"),
            3 => write!(f, "(3) - QAM8"),
            4 => write!(f, "(4) - QAM16"),
            5 => write!(f, "(5) - QAM32"),
            6 => write!(f, "(6) - QAM64"),
            7 => write!(f, "(7) - QAM128"),
            n => f.debug_tuple("QueryScQamModulationType").field(&n).finish(),
        }
    }
}

struct PwType(u16);
impl fmt::Display for PwType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            12 => write!(f, "(0x000C) - MPTPW, MPT Pseudowire Type"),
            13 => write!(f, "(0x000D) -  PSPPW, PSP Pseudowire"),
            n => f.debug_tuple("PwType").field(&n).finish(),
        }
    }
}
struct DepiPwSubtype(u16);
impl fmt::Display for DepiPwSubtype {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            1 => write!(f, "(1) - MPT-DEPI-PW, MPT DEPI Pseudowire Subtype"),
            15 => write!(f, "(15) - PSP-SPECMAN Pseudowire Subtype"),
            16 => write!(f, "(16) - PSP-PNM Pseudowire Subtype"),
            18 => write!(f, "(18) - MPT-55-1-RET Pseudowire Subtype"),
            21 => write!(f, "(21) - PSP-NDF Pseudowire Subtype"),
            22 => write!(f, "(22) - PSP-NDR Pseudowire Subtype"),
            n => f.debug_tuple("DepiPwSubtype").field(&n).finish(),
        }
    }
}
struct L2SublayerType(u16);
impl fmt::Display for L2SublayerType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            3 => write!(f, "(3) - MPT L2-Specific Sublayer Type."),
            4 => write!(f, "(4) - PSP L2-Specific Sublayer Type."),
            n => f.debug_tuple("L2SublayerType").field(&n).finish(),
        }
    }
}
struct L2SublayerSubType(u16);
impl fmt::Display for L2SublayerSubType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            1 => write!(f, "(1) - MPT DEPI L2-Specific Sublayer Subtype."),
            15 => write!(f, "(15) - PSP-SPECMAN L2-Specific Sublayer Subtype."),
            16 => write!(f, "(16) - PSP-PNM L2-Specific Sublayer Subtype."),
            18 => write!(f, "(18) - MPT-55-1-RET L2-Specific Sublayer Subtype."),
            21 => write!(f, "(21) - PSP-NDF L2-Specific Sublayer Subtype."),
            22 => write!(f, "(22) - PSP-NDR L2-Specific Sublayer Subtype."),
            n => f.debug_tuple("L2SublayerSubType").field(&n).finish(),
        }
    }
}

struct ChannelType(u8);
impl fmt::Display for ChannelType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            3 => write!(f, "(3) - DS-SCQAM"),
            6 => write!(f, "(6) - SCTE-55-1-FWD"),
            7 => write!(f, "(7) - SCTE-55-1-RET"),
            10 => write!(f, "(10) - NDF"),
            11 => write!(f, "(11) - NDR"),
            12 => write!(f, "(12) - PNM-UTSC-SAC"),
            n => f.debug_tuple("ChannelType").field(&n).finish(),
        }
    }
}

struct TopLevelRpdstate(u8);
impl fmt::Display for TopLevelRpdstate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            1 => write!(f, "(1) - LocalRPDInit"),
            2 => write!(f, "(2) - NetworkAuthentication"),
            3 => write!(f, "(3) - IPAddressAssignment"),
            4 => write!(f, "(4) - WaitingTOD"),
            5 => write!(f, "(5) - ConnectPrincipalCore"),
            6 => write!(f, "(6) - WaitOperationalPrincipalCore”"),
            7 => write!(f, "(7) - OperationalPrincipalCore"),
            n => f.debug_tuple("TopLevelRpdstate").field(&n).finish(),
        }
    }
}

struct NetworkAuthenticationRpdState(u8);
impl fmt::Display for NetworkAuthenticationRpdState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            1 => write!(f, "(1) - WaitForEapReq"),
            2 => write!(f, "(2) - Execute802.1x"),
            3 => write!(f, "(3) - SleepAfterFailure"),
            4 => write!(f, "(4) - OperationalAuthenticated"),
            5 => write!(f, "(5) - OperationalNotAuthenticated"),
            n => f
                .debug_tuple("NetworkAuthenticationRpdState")
                .field(&n)
                .finish(),
        }
    }
}
struct CoreSubState(u8);
impl fmt::Display for CoreSubState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            1 => write!(f, "(1) - AuthenticateToCore"),
            2 => write!(f, "(2) - GcpConfigAuxCore"),
            3 => write!(f, "(3) - WaitForRcpIraReq"),
            4 => write!(f, "(4) - WaitForConfigRexReq"),
            5 => write!(f, "(5) - WaitOperationalAuxCore"),
            6 => write!(f, "(6) - OperationalAuxCore"),
            7 => write!(f, "(7) - OutOfService"),
            n => f.debug_tuple("CoreSubState").field(&n).finish(),
        }
    }
}

struct UsOfdmaRollOffPeriodType(u16);
impl fmt::Display for UsOfdmaRollOffPeriodType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            1 => write!(f, "(1) - 0 samples"),
            2 => write!(f, "(2) - 32 samples"),
            3 => write!(f, "(3) - 64 samples"),
            4 => write!(f, "(4) - 96 samples"),
            5 => write!(f, "(5) - 128 samples"),
            6 => write!(f, "(6) - 160 samples"),
            7 => write!(f, "(7) - 192 samples"),
            8 => write!(f, "(8) - 224 samples"),
            n => f.debug_tuple("UsOfdmaRollOffPeriodType").field(&n).finish(),
        }
    }
}

struct UsOfdmaCyclicPrefixType(u16);
impl fmt::Display for UsOfdmaCyclicPrefixType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            1 => write!(f, "(1) - 96 samples"),
            2 => write!(f, "(2) - 128 samples"),
            3 => write!(f, "(3) - 160 samples"),
            4 => write!(f, "(4) - 192 samples"),
            5 => write!(f, "(5) - 224 samples"),
            6 => write!(f, "(6) - 256 samples"),
            7 => write!(f, "(7) - 288 samples"),
            8 => write!(f, "(8) - 320 samples"),
            9 => write!(f, "(9) - 384 samples"),
            10 => write!(f, "(10) - 512 samples"),
            11 => write!(f, "(11) - 640 samples"),
            n => f.debug_tuple("UsOfdmaCyclicPrefixType").field(&n).finish(),
        }
    }
}

struct SubcarrierSpacingType(u8);
impl fmt::Display for SubcarrierSpacingType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            1 => write!(f, "(1) - 25 KHz"),
            2 => write!(f, "(2) - 50 KHz"),
            n => f.debug_tuple("SubcarrierSpacingType").field(&n).finish(),
        }
    }
}
struct UsOfdmaModulationType(u8);
impl fmt::Display for UsOfdmaModulationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            1 => write!(f, "(1) - other"),
            2 => write!(f, "(2) - zeroValued"),
            3 => write!(f, "(3) - qpsk"),
            4 => write!(f, "(4) - qam8"),
            5 => write!(f, "(5) - qam16"),
            6 => write!(f, "(6) - qam32"),
            7 => write!(f, "(7) - qam64"),
            8 => write!(f, "(8) - qam128"),
            9 => write!(f, "(9) - qam256"),
            10 => write!(f, "(10) - qam512"),
            11 => write!(f, "(11) - qam1024"),
            12 => write!(f, "(12) - qam2048"),
            13 => write!(f, "(13) - qam4096"),
            n => f.debug_tuple("UsOfdmaModulationType").field(&n).finish(),
        }
    }
}

struct PreambleType(u8);
impl fmt::Display for PreambleType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            1 => write!(f, "(1) - QPSK0"),
            2 => write!(f, "(2) - QPSK1"),
            n => f.debug_tuple("PreambleType").field(&n).finish(),
        }
    }
}

struct SubcarrierUsageType(u8);
impl fmt::Display for SubcarrierUsageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            1 => write!(f, "(1) - Other"),
            2 => write!(f, "(2) - Data"),
            3 => write!(f, "(3) - Exclude"),
            4 => write!(f, "(4) - Unused"),
            n => f.debug_tuple("SubcarrierUsageType").field(&n).finish(),
        }
    }
}
struct SidSfType(u8);
impl fmt::Display for SidSfType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            0 => write!(f, "(0) - SID is disabled"),
            1 => write!(f, "(1) - Other"),
            2 => write!(f, "(2) - Legacy (SC-QAM Ch)"),
            3 => write!(f, "(3) - Segment-header-on"),
            4 => write!(f, "(4) - Segment-header-off"),
            n => f.debug_tuple("SidSfType").field(&n).finish(),
        }
    }
}

struct RpdConnectionStatusType(u8);
impl fmt::Display for RpdConnectionStatusType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            1 => write!(f, "(1) - Inactive"),
            2 => write!(f, "(2) - Connecting"),
            3 => write!(f, "(3) - Connected"),
            4 => write!(f, "(4) - ReConnecting"),
            n => f.debug_tuple("RpdConnectionStatusType").field(&n).finish(),
        }
    }
}

struct ResponseType(u8);
impl fmt::Display for ResponseType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            0 => write!(f, "(0) - noAction"),
            1 => write!(f, "(1) - Accept"),
            2 => write!(f, "(2) - Reject"),
            n => f.debug_tuple("ResponseType").field(&n).finish(),
        }
    }
}

struct RpdGcpBackupCoreStatusType(u8);
impl fmt::Display for RpdGcpBackupCoreStatusType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            1 => write!(f, "(1) - WaitForCoreMode"),
            2 => write!(f, "(2) - Active"),
            3 => write!(f, "(3) - Backup"),
            4 => write!(f, "(4) - CoreNotActing"),
            5 => write!(f, "(5) - Handover"),
            n => f
                .debug_tuple("RpdGcpBackupCoreStatusType")
                .field(&n)
                .finish(),
        }
    }
}

struct OperationalStatusType(u8);
impl fmt::Display for OperationalStatusType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            1 => write!(f, "(1) - up"),
            2 => write!(f, "(2) - down"),
            n => f.debug_tuple("OperationalStatusType").field(&n).finish(),
        }
    }
}

struct RpdResetType(u8);
impl fmt::Display for RpdResetType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            1 => write!(f, "(1) - softReset"),
            2 => write!(f, "(2) - hardReset"),
            3 => write!(f, "(3) - nvReset"),
            4 => write!(f, "(4) - factoryReset"),
            n => f.debug_tuple("RpdResetType").field(&n).finish(),
        }
    }
}

struct FileControlType(u8);
impl fmt::Display for FileControlType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            1 => write!(f, "(1) - other"),
            2 => write!(f, "(2) - upload"),
            3 => write!(f, "(3) - cancelUpload"),
            4 => write!(f, "(4) - deleteFile"),
            n => f.debug_tuple("FileControlType").field(&n).finish(),
        }
    }
}

struct UscStatusType(u8);
impl fmt::Display for UscStatusType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            1 => write!(f, "(1) - other"),
            2 => write!(f, "(2) - inactive"),
            3 => write!(f, "(3) - busy"),
            4 => write!(f, "(4) - sampleReady"),
            5 => write!(f, "(5) - error"),
            6 => write!(f, "(6) - resourceUnavailable"),
            7 => write!(f, "(7) - sampleTruncated"),
            n => f.debug_tuple("UscStatusType").field(&n).finish(),
        }
    }
}

struct ScCfgTrigModeType(u8);
impl fmt::Display for ScCfgTrigModeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            1 => write!(f, "(1) - other"),
            2 => write!(f, "(2) - freeRunning"),
            3 => write!(f, "(3) - miniSlotCount"),
            4 => write!(f, "(4) - sid"),
            5 => write!(f, "(5) - no used"),
            6 => write!(f, "(6) - quietProbeSymbol"),
            7 => write!(f, "(7) - burstluc"),
            8 => write!(f, "(7) - activeProveSymbol"),
            9 => write!(f, "(7) - activeProbeSymbol"),
            n => f.debug_tuple("ScCfgTrigModeType").field(&n).finish(),
        }
    }
}

struct ScCfgTrigIucType(u8);
impl fmt::Display for ScCfgTrigIucType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            1 => write!(f, "(1) - other"),
            2 => write!(f, "(2) - luc1"),
            3 => write!(f, "(3) - luc2"),
            4 => write!(f, "(4) - luc3"),
            5 => write!(f, "(5) - luc4"),
            6 => write!(f, "(6) - luc5"),
            7 => write!(f, "(7) - luc6"),
            8 => write!(f, "(8) - luc9"),
            9 => write!(f, "(9) - luc10"),
            10 => write!(f, "(10) - luc11"),
            11 => write!(f, "(11) - luc12"),
            12 => write!(f, "(12) - luc13"),
            n => f.debug_tuple("ScCfgTrigIucType").field(&n).finish(),
        }
    }
}

//*********************************************
//** Support helpers - start
fn to_ipv4(bytes: &[u8]) -> Ipv4Addr {
    //
    let ip_raw: [u8; 4] = (&bytes[0..4]).try_into().unwrap();

    Ipv4Addr::from(ip_raw)
}

fn to_ipv6(bytes: &[u8]) -> Ipv6Addr {
    let ip_raw: [u8; 16] = (&bytes[0..16]).try_into().unwrap();

    Ipv6Addr::from(ip_raw)
}

fn to_u16(bytes: &[u8]) -> u16 {
    //
    let raw: [u8; 2] = (&bytes[0..2]).try_into().unwrap();

    u16::from_be_bytes(raw)
}

fn to_u32(bytes: &[u8]) -> u32 {
    let raw: [u8; 4] = (&bytes[0..4]).try_into().unwrap();

    u32::from_be_bytes(raw)
}

fn to_u64(bytes: &[u8]) -> u64 {
    let raw: [u8; 8] = (&bytes[0..8]).try_into().unwrap();

    u64::from_be_bytes(raw)
}

fn to_bitflags<'a>(name: &str, value: u32, bit_n: usize, flags_size: usize) -> Cow<'a, str> {
    //bit_n: 0..x
    let bit_sum = value & (1 << bit_n); // shifts to bit and perform a sum operation

    // We only need if a bit was set. when sum is zero, we know no bit was set.
    let sbit = if bit_sum == 0 {
        ("0", "Not Set")
    } else {
        ("1", "Set")
    };

    let prefix = flags_size - (bit_n + 1);
    let left = ".".repeat(prefix);
    let right = ".".repeat(flags_size - (prefix + 1));
    let bits = format!("{left}{}{right}", sbit.0);

    let flags = match flags_size {
        8 => {
            format!("{} {}", &bits[0..4], &bits[4..8])
        }
        16 => {
            format!(
                "{} {} {} {}",
                &bits[0..4],
                &bits[4..8],
                &bits[8..12],
                &bits[12..16]
            )
        }
        32 => {
            format!(
                "{} {} {} {} {} {} {} {}",
                &bits[0..4],
                &bits[4..8],
                &bits[8..12],
                &bits[12..16],
                &bits[16..20],
                &bits[20..24],
                &bits[24..28],
                &bits[28..32]
            )
        }
        _ => panic!("Error: Unsupported binflag size"),
    };

    let rstr = format!("{flags} = {name}: {}", sbit.1);
    // let mut buf = String::with_capacity(rstr.chars().count());
    // buf.push_str(rstr.as_str());
    // buf.into()

    // let bitmask_string = String::from(rstr.as_str());
    // bitmask_string.into()

    String::from(rstr.as_str()).into()
}

fn to_date_rfc2578<'a>(date_tlv: &RphyTlv) -> Cow<'a, str> {
    // let object: rasn_smi::v2::ObjectSyntax =
    //     rasn::ber::decode(i.val).expect("boo");
    // let (_, obj) = parse_ber(i.val).expect("Something wong");
    // parse_ber::parse

    // DateAndTime: RFC2578
    // TODO: look at chrono crate .to_rfc2822, .to_rfc3339 and .to_rfc3339_opts
    if date_tlv.len == 8 {
        String::from(str::from_utf8(date_tlv.val).unwrap().trim_end_matches('\0')).into()
    } else if date_tlv.len == 11 {
        let _y = to_u16(&date_tlv.val[0..=1]);
        let _m = date_tlv.val[2];
        let _d = date_tlv.val[3];
        let _h = date_tlv.val[4];
        let _min = date_tlv.val[5];
        let _sec = date_tlv.val[6];
        let _dsec = date_tlv.val[7];
        let _dir = date_tlv.val[8] as char;
        let _h_utc = date_tlv.val[9];
        let _min_utc = date_tlv.val[10];
        let date_time = format!(
            "{}-{}-{},{}:{}:{}.{},{}{}:{}",
            _y, _m, _d, _h, _min, _sec, _dsec, _dir, _h_utc, _min_utc
        );

        String::from(date_time.as_str()).into()
    } else {
        //
        String::from("Unable to parse into date.").into()
    }
}

//** Support helpers - end
//*********************************************

pub fn parse_rphy_tlvs(input: &[u8], margin_base: usize) {
    let (_, sequences) = many1(parse_tlvs)(input).unwrap();

    for seq in sequences.iter() {
        println!("{}Sequence:", " ".repeat(margin_base));
        let (_, tlvs) = many1(parse_tlvs)(seq.val).unwrap();

        for tlv in tlvs.iter() {
            // TODO: Fix - having tlv_decude function is unecesary. move to a match here instead
            tlv_decode(tlv, margin_base + 2);
        }
    }
}
//parse_rphy_tlvs
fn parse_tlvs(i: &[u8]) -> IResult<&[u8], RphyTlv> {
    let (i, t) = be_u8(i)?;
    let (i, l) = be_u16(i)?;
    let (i, v) = take(l)(i)?;

    let tlv = RphyTlv {
        typ: t,
        len: l,
        val: v,
    };

    Ok((i, tlv))
}

fn tlv_decode(tlv: &RphyTlv, margin_base: usize) {
    // TODO: Create an Enum or struct to represent tlv.typ
    // let margin = MARGIN + 4;
    let mar = " ".repeat(margin_base);

    match tlv.typ {
        10 => println!("{mar}SequenceNumber: {}", to_u16(tlv.val)),
        11 => println!("{mar}Operation: {}", Operation(tlv.val[0])),
        12 => {
            println!("{mar}RfChannelSelector:");
            // tlv_rfchannelselector(tlv, margin_base + 2)
            let (_, tlvs) = many1(parse_tlvs)(tlv.val).unwrap();
            let _m = " ".repeat(margin_base + 2);
            for t in tlvs.iter() {
                match t.typ {
                    1 => println!("{_m}RfPortIndex: {}", t.val[0]),
                    2 => println!("{_m}RfChannelType: {}", RfChannelType(t.val[0])),
                    3 => println!("{_m}RfChannelIndex: {}", t.val[0]),
                    _ => println!("{_m}Unsupported RfChannelSelector sub-type"),
                };
            }
        }
        13 => {
            println!("{mar}RfPortSelector:");

            let (_, ps) = many1(parse_tlvs)(tlv.val).unwrap();
            let _m = " ".repeat(margin_base + 2);
            //TODO: Assuming these two are always included.
            println!("{_m}RfPortIndex1: {}", ps[0].val[0]);
            println!("{_m}RfPortType: {}", RfPortType(ps[1].val[0]));
        }
        14 => println!("{mar}EnetPortIndex: {}", tlv.val[0]),
        15 => {
            //RpdGlobal -
            complex_tlv_rpdglobal(tlv, margin_base);
        }
        16 => {
            //RfChannel -
            println!("{}RfChannel:", " ".repeat(margin_base));
            let (_, tlvs) = many1(parse_tlvs)(tlv.val).unwrap();
            let _m = " ".repeat(margin_base + 2);
            for t in tlvs.iter() {
                match t.typ {
                    12 => {
                        // TODO: Fix TLV has value lists
                        println!("{_m}RfChannelSelector:");
                        let _m = " ".repeat(margin_base + 4);
                        let (_, tlvs) = many1(parse_tlvs)(t.val).unwrap();
                        for t in tlvs.iter() {
                            // println!("{_m}name: Type:{}:{:?}", t.typ, t.val);
                            match t.typ {
                                1 => println!("{_m}RfPortIndex: {}", t.val[0]),
                                2 => println!("{_m}RfChannelType: {}", RfChannelType(t.val[0])),
                                3 => println!("{_m}RfChannelIndex: {}", t.val[0]),
                                _ => println!("{_m}Unknown RfChannelSelector sub-type"),
                            }
                        }
                    }
                    13 => {
                        // TODO: Fix TLV has value lists
                        println!("{_m}RfPortSelector:");
                        let _m = " ".repeat(margin_base + 4);
                        let (_, tlvs) = many1(parse_tlvs)(t.val).unwrap();
                        for t in tlvs.iter() {
                            // println!("{_m}name: Type:{}:{:?}", t.typ, t.val);
                            match t.typ {
                                1 => println!("{_m}RfPortIndex1: {}", t.val[0]),
                                2 => println!("{_m}RfPortType: {}", t.val[0]),
                                _ => println!("{_m}Unknown RfPortSelector sub-type"),
                            }
                        }
                    }
                    62 => {
                        println!("{_m}DsScQamChannelConfig:");
                        // println!("{_m}noidea: Type:{}:{:?}", t.typ, t.val)
                        complex_tlv_dsscqamchannelconfig(t, margin_base + 4);
                    }
                    91 => {
                        //complex_tlv_dsoob55d1(t, margin_base + 4);
                        println!("{_m}DsOob55d1:");
                        let _m4 = " ".repeat(margin_base + 4);
                        let (_, tlvs) = many1(parse_tlvs)(t.val).unwrap();
                        for t in tlvs.iter() {
                            match t.typ {
                                1 => println!("{_m4}AdminState: {}", AdminStateType(t.val[0])),
                                2 => println!("{_m4}CcapCoreOwner: {}", HexFmt(t.val)),
                                3 => {
                                    let _s = match t.val[0] {
                                        0 => "(0) - Channel is not muted.".to_string(),
                                        1 => "(1) - Channel is muted.".to_string(),
                                        _ => "Reserved".to_string(),
                                    };
                                    println!("{_m4}RfMute: {_s}");
                                }
                                4 => println!("{_m4}Frequency: {} Hertz", to_u32(t.val)),
                                5 => println!("{_m4}PowerAdjust: {} TenthdB", to_u16(t.val)),
                                6 => println!("{_m4}SecondFrequency: {} Hertz", to_u32(t.val)),
                                7 => println!("{_m4}SfPowerAdjust: {} TenthdB", to_u16(t.val)),
                                8 => println!("{_m4}SfAdminState: {}", AdminStateType(t.val[0])),
                                9 => {
                                    let _s = match t.val[0] {
                                        0 => "(0) - Channel is not muted.".to_string(),
                                        1 => "(1) - Channel is muted.".to_string(),
                                        _ => "Reserved".to_string(),
                                    };
                                    println!("{_m4}SfPowerAdjust: {_s}");
                                }
                                _ => println!("{_m4}Unknown DsOob55d1 sub-type"),
                            }
                        }
                    }

                    92 => {
                        // TODO: Decode UsOob55d1 here
                        //complex_tlv_usoob55d1(t, margin_base + 4);

                        println!("{_m}UsOob55d1:");

                        let (_, tlvs) = many1(parse_tlvs)(t.val).unwrap();
                        let _m4 = " ".repeat(margin_base + 4);
                        for t in tlvs.iter() {
                            match t.typ {
                                1 => println!("{_m4}AdminState: {}", AdminStateType(t.val[0])),
                                2 => println!("{_m4}CcapCoreOwner: {:X}", HexFmt(t.val)),
                                3 => println!("{_m4}Frequency: {} Hertz", to_u32(t.val)),
                                4 => println!("{_m4}VarpdDeviceId: {}", to_u32(t.val)),
                                5 => println!("{_m4}VarpdRfPortId: {}", t.val[0]),
                                6 => println!("{_m4}VarpdDemodId: {}", t.val[0]),
                                7 => {
                                    println!("{_m4}TargetRxPowerAdjust: {} TenthdB", to_u16(t.val))
                                }
                                _ => println!("{_m4}Unsupported UsOob55d1 sub-type"),
                            };
                        }
                    }
                    _ => println!(
                        "{_m}Unsupported RfChannel sub-type: Type:{}:{:?}",
                        t.typ, t.val
                    ),
                };
            }
        }
        19 => {
            println!(
                "{}ResponseCode: {}",
                " ".repeat(margin_base),
                ResponseCode(tlv.val[0])
            );
        }
        50 => {
            //RpdGlobal -
            if tlv.len == 0 {
                println!("{}RpdCapabilities: [Empty]", " ".repeat(margin_base));
            } else {
                // TODO: peek a type byte to and create a match for 50.19
                // println!("{}RpdCapabilities:", " ".repeat(margin_base));
                complex_tlv_rpdcapabilities(tlv, margin_base + 2);
            }
        }
        58 => {
            println!("{mar}StaticPwConfig:");
            complex_tlv_staticpwconfig(tlv, margin_base + 2);
        }
        59 => {
            println!("{}StaticPwStatus:", " ".repeat(margin_base));

            let (_, tlvs) = many1(parse_tlvs)(tlv.val).unwrap();
            let _m = " ".repeat(margin_base + 2);
            let _m4 = " ".repeat(margin_base + 4);
            for t in tlvs.iter() {
                match t.typ {
                    1 => {
                        println!("{_m}CommonStaticPwStatus:");
                        let (_, tlvs) = many1(parse_tlvs)(tlv.val).unwrap();
                        for t in tlvs.iter() {
                            match t.typ {
                                1 => {
                                    let _s = match t.val[0] {
                                        0 => "(0) - forward direction pseudowire (from CCAP Core to the RPD).".to_string(),
                                        1 => "(1) - return direction pseudowire (from RPD to the CCAP Core).".to_string(),
                                        _ => "Reserved".to_string(),
                                    };
                                    println!("{_m4}Direction: {_s}")
                                }
                                2 => println!("{_m4}Index: {}", to_u16(t.val)),
                                // TODO: RpdCircuitStatus is a bit field: bit 15 A and bit 14 N - See: RpdCircuitStatus
                                3 => println!("{_m4}RpdCircuitStatus: {}", to_u16(t.val)),
                                4 => println!("{_m4}RpdSelectedSessionId: {}", to_u32(t.val)),
                                _ => println!("{_m4}Unsupported CommonStaticPwStatus sub-type"),
                            };
                        }
                    }
                    _ => println!("{_m}Unsupported StaticPwStatus sub-type"),
                };
            }
            /*
            StaticPwStatus	                Complex TLV	                        59	variable
                CommonStaticPwStatus	        Complex TLV	                        59.1	variable
                    Direction	                    UnsignedByte	                    59.1.1	1
                    Index	                        UnsignedShort	                    59.1.2	2
                    RpdCircuitStatus	            UnsignedShort	                    59.1.3	2
                    RpdSelectedSessionId	        UnsignedInt	                        59.1.4	4
            */
        }
        60 => {
            // B.5.5.8 CCAP Core Identification
            println!("{}CcapCoreIdentification", " ".repeat(margin_base));
            complex_tvl_ccapcoreidentification(tlv, margin_base + 2);
        }
        61 => {
            println!("{}DsRfPort:", " ".repeat(margin_base));
            complex_tlv_dsrfport(tlv, margin_base + 2);
        }
        62 => {
            println!("{mar}DsScQamChannelConfig:");
            complex_tlv_dsscqamchannelconfig(tlv, margin_base + 2);
        }
        63 => {
            println!("{mar}DsOfdmChannelConfig:");
            complex_tlv_dsofdmchannelconfig(tlv, margin_base + 2);
        }
        64 => {
            println!("{mar}DsOfdmProfile:");
            complex_tlv_dsofdmprofile(tlv, margin_base + 2);
        }
        65 => {
            println!("{mar}UsScQamChannelConfig:");
            complex_tlv_usscqamchannelconfig(tlv, margin_base + 2);
        }
        66 => {
            println!("{mar}UsOfdmaChannelConfig:");
            complex_tlv_usofdmachannelconfig(tlv, margin_base + 2);
        }
        67 => {
            println!("{mar}UsOfdmaInitialRangingIuc:");
            let (_, tlvs) = many1(parse_tlvs)(tlv.val).unwrap();
            let _m = " ".repeat(margin_base + 2);
            for t in tlvs.iter() {
                match t.typ {
                    1 => println!("{_m}NumSubcarriers: {}", to_u16(t.val)),
                    2 => println!("{_m}Guardband: {}", to_u16(t.val)),
                    _ => println!("{_m}Unsupported UsOfdmaInitialRangingIuc sub-type"),
                };
            }
        }
        68 => {
            println!("{mar}UsOfdmaFineRangingIuc:");
            let (_, tlvs) = many1(parse_tlvs)(tlv.val).unwrap();
            let _m = " ".repeat(margin_base + 2);
            for t in tlvs.iter() {
                match t.typ {
                    1 => println!("{_m}NumSubcarriers: {}", to_u16(t.val)),
                    2 => println!("{_m}Guardband: {}", to_u16(t.val)),
                    _ => println!("{_m}Unsupported UsOfdmaFineRangingIuc sub-type"),
                };
            }
        }
        69 => {
            println!("{mar}UsOfdmaDataIuc:");
            let (_, tlvs) = many1(parse_tlvs)(tlv.val).unwrap();
            let _m = " ".repeat(margin_base + 2);
            for t in tlvs.iter() {
                match t.typ {
                    1 => println!("{_m}DataIuc: {}", t.val[0]),
                    2 => println!("{_m}StartMinislot: {}", to_u16(t.val)),
                    3 => println!("{_m}FirstSubcarrierId: {}", to_u16(t.val)),
                    4 => println!("{_m}NumConsecutiveMinislots: {}", to_u16(t.val)),
                    5 => println!("{_m}MinislotPilotPattern: {}", t.val[0]),
                    6 => println!(
                        "{_m}DataSymbolModulation: {}",
                        UsOfdmaModulationType(t.val[0])
                    ),
                    _ => println!("{_m}Unsupported UsOfdmaDataIuc sub-type"),
                };
            }
        }
        70 => {
            println!("{mar}UsOfdmaSubcarrierCfgState:");
            let (_, tlvs) = many1(parse_tlvs)(tlv.val).unwrap();
            let _m = " ".repeat(margin_base + 2);
            for t in tlvs.iter() {
                match t.typ {
                    1 => println!("{_m}StartingSubcarrierId: {}", to_u16(t.val)),
                    2 => println!("{_m}NumConsecutiveSubcarriers: {}", to_u16(t.val)),
                    3 => println!("{_m}SubcarrierUsage: {}", SubcarrierUsageType(t.val[0])),
                    _ => println!("{_m}Unsupported UsOfdmaSubcarrierCfgState sub-type"),
                };
            }
        }
        71 => {
            println!("{mar}DsRfPortPerf:");
            let (_, tlvs) = many1(parse_tlvs)(tlv.val).unwrap();
            let _m = " ".repeat(margin_base + 2);
            for t in tlvs.iter() {
                match t.typ {
                    1 => println!(
                        "{_m}operStatusDsRfPort: {}",
                        OperationalStatusType(t.val[0])
                    ),
                    _ => println!("{_m}Unsupported DsRfPortPerf sub-type"),
                };
            }
        }
        72 => {
            println!("{mar}DsScQamChannelPerf:");
            let (_, tlvs) = many1(parse_tlvs)(tlv.val).unwrap();
            let _m = " ".repeat(margin_base + 2);
            for t in tlvs.iter() {
                match t.typ {
                    1 => println!("{_m}outDiscards: {} packets", to_u64(t.val)),
                    2 => println!("{_m}outErrors: {} packets", to_u64(t.val)),
                    3 => println!("{_m}outPackets: {} packets", to_u64(t.val)),
                    4 => println!("{_m}discontinuityTime: {}", to_date_rfc2578(t)),
                    5 => println!("{_m}operStatusDsScQam: {}", OperationalStatusType(t.val[0])),
                    _ => println!("{_m}Unsupported DsScQamChannelPerf sub-type"),
                };
            }
        }
        73 => {
            complex_tlv_dsofdmchannelperf(tlv, margin_base);
        }
        74 => {
            println!("{mar}DsOob551Perf:");
            let (_, tlvs) = many1(parse_tlvs)(tlv.val).unwrap();
            let _m = " ".repeat(margin_base + 2);
            for t in tlvs.iter() {
                match t.typ {
                    1 => println!("{_m}outDiscards: {} packets", to_u64(t.val)),
                    2 => println!("{_m}outErrors: {} packets", to_u64(t.val)),
                    3 => println!("{_m}outPackets: {} packets", to_u64(t.val)),
                    4 => println!("{_m}discontinuityTime: {}", to_date_rfc2578(t)),
                    5 => println!(
                        "{_m}operStatusDsOob551: {}",
                        OperationalStatusType(t.val[0])
                    ),
                    _ => println!("{_m}Unsupported DsOob551Perf sub-type"),
                };
            }
        }
        75 => {
            println!("{mar}DsOob552Perf:");
            let (_, tlvs) = many1(parse_tlvs)(tlv.val).unwrap();
            let _m = " ".repeat(margin_base + 2);
            for t in tlvs.iter() {
                match t.typ {
                    1 => println!("{_m}outDiscards: {} packets", to_u64(t.val)),
                    2 => println!("{_m}outErrors: {} packets", to_u64(t.val)),
                    3 => println!("{_m}outPackets: {} packets", to_u64(t.val)),
                    4 => println!("{_m}discontinuityTime: {}", to_date_rfc2578(t)),
                    5 => println!(
                        "{_m}operStatusDsOob552: {}",
                        OperationalStatusType(t.val[0])
                    ),
                    _ => println!("{_m}Unsupported DsOob552Perf sub-type"),
                };
            }
        }
        76 => {
            println!("{mar}NdfPerf:");
            let (_, tlvs) = many1(parse_tlvs)(tlv.val).unwrap();
            let _m = " ".repeat(margin_base + 2);
            for t in tlvs.iter() {
                match t.typ {
                    1 => println!("{_m}outDiscards: {} packets", to_u64(t.val)),
                    2 => println!("{_m}outErrors: {} packets", to_u64(t.val)),
                    3 => println!("{_m}outPackets: {} packets", to_u64(t.val)),
                    4 => println!("{_m}discontinuityTime: {}", to_date_rfc2578(t)),
                    5 => println!("{_m}operStatusNdf: {}", OperationalStatusType(t.val[0])),
                    _ => println!("{_m}Unsupported NdfPerf sub-type"),
                };
            }
        }
        77 => {
            println!("{mar}UsRfPortPerf:");
            let (_, tlvs) = many1(parse_tlvs)(tlv.val).unwrap();
            let _m = " ".repeat(margin_base + 2);
            for t in tlvs.iter() {
                match t.typ {
                    1 => println!(
                        "{_m}operStatusUsRfPort: {}",
                        OperationalStatusType(t.val[0])
                    ),
                    _ => println!("{_m}Unsupported UsRfPortPerf sub-type"),
                };
            }
        }
        78 => {
            complex_tlv_usscqamchannelperf(tlv, margin_base);
        }
        79 => {
            complex_tlv_usofdmachannelperf(tlv, margin_base);
        }
        80 => {
            println!("{mar}UsOob551Perf:");
            let (_, tlvs) = many1(parse_tlvs)(tlv.val).unwrap();
            let _m = " ".repeat(margin_base + 2);
            for t in tlvs.iter() {
                match t.typ {
                    1 => println!(
                        "{_m}operStatusUsOob551: {}",
                        OperationalStatusType(t.val[0])
                    ),
                    _ => println!("{_m}Unsupported UsOob551Perf sub-type"),
                };
            }
        }
        81 => {
            println!("{mar}UsOob552Perf:");
            let (_, tlvs) = many1(parse_tlvs)(tlv.val).unwrap();
            let _m = " ".repeat(margin_base + 2);
            for t in tlvs.iter() {
                match t.typ {
                    1 => println!(
                        "{_m}operStatusUsOob552: {}",
                        OperationalStatusType(t.val[0])
                    ),
                    _ => println!("{_m}Unsupported UsOob552Perf sub-type"),
                };
            }
        }
        82 => {
            println!("{mar}NdrPerf:");
            let (_, tlvs) = many1(parse_tlvs)(tlv.val).unwrap();
            let _m = " ".repeat(margin_base + 2);
            for t in tlvs.iter() {
                match t.typ {
                    1 => println!("{_m}operStatusNdr: {}", OperationalStatusType(t.val[0])),
                    _ => println!("{_m}Unsupported NdrPerf sub-type"),
                };
            }
        }
        86 => {
            println!("{}GeneralNotification", " ".repeat(margin_base));
            let (_, gn) = many1(parse_tlvs)(tlv.val).unwrap();
            let _mar = margin_base + 2;

            for g in gn.iter() {
                //
                match g.typ {
                    1 => {
                        let not_type = match g.val[0] {
                            1 => "1 - StartUpNotification".to_string(),
                            2 => "2 - RedirectResultNotification".to_string(),
                            3 => "3 - PtpResultNotification".to_string(),
                            4 => "4 - AuxCoreResultNotification".to_string(),
                            5 => "5 - TimeOutNotification".to_string(),
                            6 => "6 - Deprecated".to_string(),
                            7 => "7 - ReconnectNotification".to_string(),
                            8 => "8 - AuxCoreGcpStatusNotification".to_string(),
                            9 => "9 - ChannelUcdRefreshRequest".to_string(),
                            10 => "10 - HandoverNotification".to_string(),
                            11 => "11 - SsdFailureNotification".to_string(),
                            _ => "NotificationType".to_string(),
                        };

                        println!("{}NotificationType: {}", " ".repeat(_mar), not_type);
                    }
                    2 => {
                        println!("{}RedirectResult: {}", " ".repeat(_mar), g.val[0]);
                    }
                    3 => {
                        if g.len == 4 {
                            println!(
                                "{}RpdRedirectIpAddress: {}",
                                " ".repeat(_mar),
                                to_ipv4(g.val)
                            );
                        } else if g.len == 16 {
                            println!(
                                "{}RpdRedirectIpAddress: {}",
                                " ".repeat(_mar),
                                to_ipv6(g.val)
                            );
                        } else {
                            //
                            println!(
                                "{}RpdRedirectIpAddress: Invalid IP format.",
                                " ".repeat(_mar)
                            );
                        }
                    }
                    4 => {
                        println!("{}PtpRpdEnetPortIndex: {}", " ".repeat(_mar), g.val[0]);
                    }
                    5 => {
                        println!("{}PtpResult: {}", " ".repeat(_mar), g.val[0]);
                    }
                    6 => {
                        println!("{}AuxCoreResult: {}", " ".repeat(_mar), g.val[0]);
                    }
                    7 => {
                        if g.len == 4 {
                            println!("{}AuxCoreIpAddress: {}", " ".repeat(_mar), to_ipv4(g.val));
                        } else if g.len == 16 {
                            //
                            println!("{}AuxCoreIpAddress: {}", " ".repeat(_mar), to_ipv6(g.val));
                        } else {
                            println!("{}AuxCoreIpAddress: Invalid IP format.", " ".repeat(_mar));
                        }
                    }
                    8 => {
                        println!("{}AuxCoreFailureType: {}", " ".repeat(_mar), g.val[0]);
                    }
                    9 => {
                        println!("{}SpecificTimeOut: {}", " ".repeat(_mar), g.val[0]);
                    }
                    10 => {
                        if g.len == 4 {
                            //
                            println!(
                                "{}CoreTimedOutIpAddress: {}",
                                " ".repeat(_mar),
                                to_ipv4(g.val)
                            );
                        } else if g.len == 16 {
                            //
                            println!(
                                "{}CoreTimedOutIpAddress: {}",
                                " ".repeat(_mar),
                                to_ipv6(g.val)
                            );
                        }
                    }
                    11 => {
                        println!("{}PtpRpdPtpPortIndex: {}", " ".repeat(_mar), g.val[0]);
                    }
                    12 => {
                        println!("{}PtpClockSource: {}", " ".repeat(_mar), g.val[0]);
                    }
                    13 => {
                        println!(
                            "{}AuxCoreGcpConnectionStatus: {}",
                            " ".repeat(_mar),
                            g.val[0]
                        );
                    }
                    14 => {
                        println!("{}AuxCoreId: {}", " ".repeat(_mar), HexFmt(g.val));
                    }
                    15 => {
                        println!("{}SsdFailureType: {}", " ".repeat(_mar), to_u32(g.val));
                    }
                    _ => {
                        println!("{}Unknown: {:?}", " ".repeat(_mar), g.val);
                    }
                };
            }
        }
        87 => {
            complex_tlv_rpdstate(tlv, margin_base);
        }
        91 => {
            complex_tlv_dsoob55d1(tlv, margin_base);
        }
        92 => {
            complex_tlv_usoob55d1(tlv, margin_base);
        }
        96 => {
            println!("{mar}SidQos:");
            let (_, tlvs) = many1(parse_tlvs)(tlv.val).unwrap();
            let _m = " ".repeat(margin_base + 2);
            for t in tlvs.iter() {
                match t.typ {
                    1 => println!("{_m}StartSid: {}", to_u16(t.val)),
                    2 => println!("{_m}NumSids: {}", to_u16(t.val)),
                    3 => println!("{_m}SidSfType: {}", SidSfType(t.val[0])),
                    4 => println!("{_m}SidUepiFlowId: {}", t.val[0]),
                    5 => println!("{_m}SidFlowTag: {}", to_u32(t.val)),
                    6 => println!("{_m}FlowTagIncrement: {}", t.val[0]),
                    _ => println!("{_m}Unsupported SidQos sub-type"),
                };
            }
        }
        98 => {
            complex_tlv_usrfport(tlv, margin_base);
        }
        105 => {
            println!("{mar}RpdConnectionStatus:");
            let (_, tlvs) = many1(parse_tlvs)(tlv.val).unwrap();
            let _m2 = " ".repeat(margin_base + 2);
            for t in tlvs.iter() {
                match t.typ {
                    1 => println!("{_m2}Index: {}", t.val[0]),
                    2 => println!("{_m2}CoreId: {}", HexFmt(t.val)),
                    3 => println!(
                        "{_m2}RpdGcpConnectionStatus: {}",
                        RpdConnectionStatusType(t.val[0])
                    ),
                    _ => println!("{_m2}Unsupported RpdConnectionStatus sub-type"),
                };
            }
        }
        106 => {
            println!("{mar}CoreGcpConnectionResponse:");
            let (_, tlvs) = many1(parse_tlvs)(tlv.val).unwrap();
            let _m2 = " ".repeat(margin_base + 2);
            for t in tlvs.iter() {
                match t.typ {
                    1 => println!("{_m2}CoreId: {}", HexFmt(t.val)),
                    2 => println!("{_m2}Response: {}", ResponseType(t.val[0])),
                    _ => println!("{_m2}Unsupported CoreGcpConnectionResponse sub-type"),
                };
            }
        }
        107 => {
            println!("{mar}RpdBackupCoreStatus:");
            let (_, tlvs) = many1(parse_tlvs)(tlv.val).unwrap();
            let _m2 = " ".repeat(margin_base + 2);
            for t in tlvs.iter() {
                match t.typ {
                    1 => println!("{_m2}Index: {}", t.val[0]),
                    2 => println!("{_m2}CoreId: {}", HexFmt(t.val)), //hexbinary
                    3 => println!(
                        "{_m2}RpdGcpBackupCoreStatus: {}",
                        RpdGcpBackupCoreStatusType(t.val[0])
                    ),
                    _ => println!("{_m2}Unsupported RpdBackupCoreStatus sub-type"),
                };
            }
        }
        108 => {
            println!("{mar}CoreGcpBackupResponse:");
            let (_, tlvs) = many1(parse_tlvs)(tlv.val).unwrap();
            let _m2 = " ".repeat(margin_base + 2);
            for t in tlvs.iter() {
                match t.typ {
                    1 => println!("{_m2}CoreId: {}", HexFmt(t.val)), //hexbinary
                    2 => println!("{_m2}Response: {}", ResponseType(t.val[0])),
                    _ => println!("{_m2}Unsupported CoreGcpBackupResponse sub-type"),
                };
            }
        }
        109 => {
            println!("{mar}GcpHandoverControl:");
            let (_, tlvs) = many1(parse_tlvs)(tlv.val).unwrap();
            let _m2 = " ".repeat(margin_base + 2);
            for t in tlvs.iter() {
                match t.typ {
                    1 => {
                        let _s = match t.val[0] {
                            0 => "(0) - noAction.".to_string(),
                            1 => "(1) - InitiateHandover.".to_string(),
                            _ => "Reserved".to_string(),
                        };
                        println!("{_m2}GcpHandoverControlAction: {_s}");
                    }
                    2 => println!("{_m2}OosCore: {}", HexFmt(t.val)), //hexbinary
                    3 => println!("{_m2}NewActiveCore: {}", HexFmt(t.val)), //hexbinary
                    4 => {
                        let _s = match t.val[0] {
                            0 => "(0) - noAction.".to_string(),
                            1 => "(1) - tearDown.".to_string(),
                            2 => "(2) - keepActive.".to_string(),
                            _ => "Reserved".to_string(),
                        };
                        println!("{_m2}L2TPv3: {_s}");
                    }
                    _ => println!("{_m2}Unsupported GcpHandoverControl sub-type"),
                };
            }
        }
        160 => {
            complex_tlv_rfmconfig(tlv, margin_base);
        }
        150 => {
            complex_tlv_usscqamprofilequery(tlv, margin_base);
        }
        151 => {
            complex_tlv_usscqamprofileresponse(tlv, margin_base);
        }
        152 => {
            println!("{}UsOfdmaConfigQuery", " ".repeat(margin_base));
            let (_, uocf) = many1(parse_tlvs)(tlv.val).unwrap();
            let _m2 = margin_base + 2;

            for t in uocf.iter() {
                match t.typ {
                    1 => println!(
                        "{_m2}QueryOfdmaRollOffPeriod: {}",
                        UsOfdmaRollOffPeriodType(to_u16(t.val))
                    ),
                    2 => println!(
                        "{_m2}QueryOfdmaCyclicPrefix: {}",
                        UsOfdmaCyclicPrefixType(to_u16(t.val))
                    ),
                    3 => println!(
                        "{_m2}QueryOfdmaSubcarrierSpacing: {}",
                        SubcarrierSpacingType(t.val[0])
                    ),
                    4 => println!("{_m2}QueryNumSymbolsPerFrame: {}", t.val[0]),
                    5 => println!("{_m2}QueryOfdmaScramblerSeed: {}", to_u32(t.val)),
                    _ => println!("{_m2}Unsupported UsOfdmaConfigQuery sub-type"),
                };
            }
        }
        153 => {
            println!("{}UsOfdmaConfigResponse", " ".repeat(margin_base));
            let (_, uocf) = many1(parse_tlvs)(tlv.val).unwrap();
            let _m2 = margin_base + 2;

            for t in uocf.iter() {
                match t.typ {
                    1 => println!(
                        "{_m2}ResponseOfdmaRollOffPeriod: {}",
                        UsOfdmaRollOffPeriodType(to_u16(t.val))
                    ),
                    2 => println!(
                        "{_m2}ResponseOfdmaCyclicPrefix: {}",
                        UsOfdmaCyclicPrefixType(to_u16(t.val))
                    ),
                    3 => {
                        println!("{_m2}ResponseOfdmaPreambleString:");
                        t.val.iter().for_each(|x| {
                            print!("{x:08b}");
                        });
                        println!(" ");
                    }
                    4 => println!("{_m2}ResponseNumSymbolsPerFrame: {}", t.val[0]),
                    5 => println!("{_m2}ResponseOfdmaScramblerSeed: {}", to_u32(t.val)),
                    _ => println!("{_m2}Unsupported UsOfdmaConfigResponse sub-type"),
                };
            }
        }
        _ => {
            print!(
                "{}Unsupported RPHY TLV: Type: {:?}, Length: {:?}, Value: {:?}",
                " ".repeat(margin_base),
                tlv.typ,
                tlv.len,
                tlv.val
            );
        }
    }
}

fn complex_tlv_rpdglobal(tlv: &RphyTlv, margin: usize) {
    println!("{}RpdGlobal:", " ".repeat(margin));

    let (_, tlvs) = many1(parse_tlvs)(tlv.val).unwrap();
    let _m = " ".repeat(margin + 2);
    let _m4 = " ".repeat(margin + 4);
    let _m6 = " ".repeat(margin + 6);
    for t in tlvs.iter() {
        match t.typ {
            1 => {
                println!("{_m}EvCfg:");

                let (_, tlvs) = many1(parse_tlvs)(t.val).unwrap();
                for t in tlvs.iter() {
                    match t.typ {
                        1 => {
                            let (_, tlvs) = many1(parse_tlvs)(t.val).unwrap();
                            println!("{_m4}EvControl:");
                            println!("{_m6}EvPriority: {}", EvPriority(tlvs[0].val[0]));
                            println!("{_m6}EvReporting: {}", tlvs[1].val[0]);
                        }
                        2 => println!(
                            "{_m4}EvThrottleAdminStatus: {}",
                            EvThrottleAdminStatus(t.val[0])
                        ),
                        3 => println!("{_m4}EvThrottleThreshold: {}", to_u32(t.val)),
                        4 => println!("{_m4}EvThrottleInterval: {} seconds", to_u32(t.val)),
                        5 => {
                            let _s = match t.val[0] {
                                0 => "(0) - The RPD is not enabled to send event reports via Notify message.".to_string(),
                                1 => "(1) - The RPD is enabled to send event reports via Notify message.".to_string(),
                                _ => "Reserved".to_string(),
                            };
                            println!("{_m4}NotifyEnable: {_s}")
                        }
                        _ => println!("{_m4}Unsupported EvCfg sub-type: {:?}", t),
                    };
                }
            }
            2 => {
                println!("{_m}GcpConnVerification:");
                let (_, tlvs) = many1(parse_tlvs)(t.val).unwrap();

                println!(
                    "{_m4}CoreId: {}",
                    format_args!(
                        "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                        tlvs[0].val[0],
                        tlvs[0].val[1],
                        tlvs[0].val[2],
                        tlvs[0].val[3],
                        tlvs[0].val[4],
                        tlvs[0].val[5]
                    )
                );
                println!("{_m4}MaxGcpIdleTime: {} seconds", to_u16(tlvs[1].val));
                println!(
                    "{_m4}GcpRecoveryAction: {}",
                    GcpRecoveryAction(tlvs[2].val[0])
                );
                println!("{_m4}GcpRecoveryActionRetry: {}", tlvs[3].val[0]);
                println!(
                    "{_m4}GcpRecoveryActionDelay: {} seconds",
                    to_u16(tlvs[4].val)
                );
                println!("{_m4}GcpReconnectTimeout: {} seconds", to_u16(tlvs[5].val));
                println!("{_m4}GcpHandoverTimeout: {} seconds", to_u16(tlvs[6].val));
            }
            3 => {
                let (_, ip) = many1(parse_tlvs)(t.val).unwrap();
                println!("{_m}IpConfig:");

                let _s = match ip[0].val[0] {
                    0 => "(0) - Dual stack IP mode operation.".to_string(),
                    1 => "(1) - IPv4-only operation.".to_string(),
                    2 => "(2) - IPv6-only operation.".to_string(),
                    _ => "Reserved".to_string(),
                };
                println!("{_m4}IpStackControl: {_s}");

                let (_, pc) = many1(parse_tlvs)(ip[1].val).unwrap();
                let _u1 = match pc[0].val[0] {
                    0 => "(0) - The RPD does not use PMTUD based on these RFCs.".to_string(),
                    1 => "(1) - The RPD uses PMTUD based on these RFCs.".to_string(),
                    _ => "Reserved".to_string(),
                };
                let _u2 = match pc[1].val[0] {
                    0 => "(0) - The RPD does not use PMTUD based on RFC4821.".to_string(),
                    1 => "(1) - The RPD uses PMTUD based on RFC4821.".to_string(),
                    _ => "Reserved".to_string(),
                };
                println!("{_m6}UseIcmpBasedPmtud: {}", _u1);
                println!("{_m6}UsePacketizationBasedPmtud: {}", _u2);
            }
            4 => {
                let (_, ue) = many1(parse_tlvs)(t.val).unwrap();

                let _u = match ue[0].val[0] {
                    0 => "(0) - The RPD does not use the UEPI RNG-REQ pseudowires for SC-QAM channels.".to_string(),
                    1 => "(1) - The RPD uses the UEPI RNG-REQ pseudowires for SC- QAM channels.".to_string(),
                    _ => "Reserved".to_string(),
                };
                println!("{_m}UepiControl:");
                println!("{_m4}ScQamUseRngPw: {_u}");
                println!("{_m4}OfdmaMaxNumPayloadUnits: {}", ue[1].val[0]);
                println!("{_m4}OfdmaMaxNumTrailerUnits: {}", ue[2].val[0]);
            }
            5 => println!("{_m}GcpDscp: {}", t.val[0]),
            6 => {
                let (_, ll) = many1(parse_tlvs)(t.val).unwrap();
                let _l = match ll[0].val[0] {
                    0 => "(0) - LLDP is disabled.".to_string(),
                    1 => "(1) - LLDP is enabled.".to_string(),
                    _ => "Reserved".to_string(),
                };
                println!("{_m}LldpConfig:");
                println!("{_m4}LldpEnable: {_l}");
                println!("{_m4}MsgTxInterval: {}", to_u16(ll[1].val));
            }
            7 => println!("{_m}CoreConnectTimeout: {}", to_u16(t.val)),
            _ => println!("{_m}Unsupported RpdGlobal sub-type"),
        };
    }
}

fn complex_tvl_ccapcoreidentification(tlv: &RphyTlv, margin: usize) {
    //
    let (_, cc) = many1(parse_tlvs)(tlv.val).unwrap();
    let is_flag_set = |x: u8| x == 1;
    let _m = " ".repeat(margin);
    let _m2 = " ".repeat(margin + 2);
    for t in cc {
        // println!("{}--> Type:{} Val:{:?}", " ".repeat(margin), t.typ, t.val);
        match t.typ {
            1 => println!("{_m}Index: {}", t.val[0]),
            2 => println!("{_m}CoreId: {:X}", HexFmt(t.val)),
            3 => {
                if t.len == 4 {
                    println!("{_m}CoreIPAddress: {}", to_ipv4(t.val));
                } else if t.len == 16 {
                    println!("{_m}CoreIPAddress: {}", to_ipv6(t.val));
                } else {
                    println!("{_m}CoreIPAddress: Unable to format: {}:{:?}", t.len, t.val);
                }
            }
            4 => println!("{_m}IsPrincipal: {}", is_flag_set(t.val[0])),
            5 => {
                println!(
                    "{_m}CoreName: {}",
                    str::from_utf8(t.val).unwrap().trim_end_matches('\0'),
                );
            }
            6 => println!("{_m}VendorId: {}", to_u16(t.val)),
            7 => println!("{_m}CoreMode: {}", CoreMode(t.val[0])),
            8 => {
                println!(
                    "{_m}InitialConfigurationComplete: {}",
                    is_flag_set(t.val[0])
                );
            }
            9 => println!("{_m}MoveToOperational: {}", is_flag_set(t.val[0])),

            10 => {
                let value = to_u16(t.val);
                println!("{_m}CoreFunction:");

                let _s = format!("{value:016b}");
                println!(
                    "{_m2}{} {} {} {} ({value:#06X})",
                    &_s[0..4],
                    &_s[4..8],
                    &_s[8..12],
                    &_s[12..16]
                );
                println!("{_m2}{}", to_bitflags("Principal", value.into(), 0, 16)); //15-
                println!("{_m2}{}", to_bitflags("DOCSIS", value.into(), 1, 16));
                println!(
                    "{_m2}{}",
                    to_bitflags("Broadcast Video", value.into(), 2, 16)
                );
                println!(
                    "{_m2}{}",
                    to_bitflags("Narrowcast Video", value.into(), 3, 16)
                );
                println!("{_m2}{}", to_bitflags("SCTE 55-1 OOB", value.into(), 4, 16));
                println!("{_m2}{}", to_bitflags("SCTE 55-2 OOB", value.into(), 5, 16));
                println!("{_m2}{}", to_bitflags("NDF", value.into(), 6, 16));
                println!("{_m2}{}", to_bitflags("NDR", value.into(), 7, 16));
                println!("{_m2}0000 0000 .... .... = Reserved");
            }
            11 => println!("{_m}ResourceSetIndex: {}", t.val[0]),
            12 => println!("{_m}(Reserved)"),
            13 => {
                let cc = match t.val[0] {
                    1 => "(1) - connection".to_string(),
                    2 => "(2) - noConection".to_string(),
                    _ => "Unknown".to_string(),
                };

                println!("{_m}GcpBackupConnectionConfig: {}", cc);
            }
            14 => {
                //table containing cores to be contacted by RPD. See page 259 60.14, 60.14.1-2
                println!("{_m}CandidateBackupCoreTable:");
                let (_, tlvs) = many1(parse_tlvs)(t.val).unwrap();
                for c in tlvs.iter() {
                    match c.typ {
                        1 => println!("{_m2}Index: {}", c.val[0]),
                        2 => {
                            if t.len == 4 {
                                println!("{_m2}BackupCoreIpAddress: {}", to_ipv4(c.val));
                            } else if t.len == 6 {
                                println!("{_m2}BackupCoreIpAddress: {}", to_ipv6(c.val));
                            } else {
                                println!("{_m2}BackupCoreIpAddress: Could not parse IP address.")
                            };
                        }
                        _ => println!("{_m2}Unsupported CandidateBackupCoreTable sub-type"),
                    };
                }
            }
            _ => {
                println!(
                    "{}Unknown: Type:{} Value:{:?}",
                    " ".repeat(margin),
                    t.typ,
                    t.val
                )
            }
        }
    }
}

fn complex_tlv_rpdcapabilities(tlv: &RphyTlv, margin: usize) {
    println!("{}RpdCapabilities:", " ".repeat(margin));

    let (_, rpdc) = many1(parse_tlvs)(tlv.val).unwrap();
    let _m2 = " ".repeat(margin + 2);
    let _m4 = " ".repeat(margin + 4);
    let _m6 = " ".repeat(margin + 6);
    let _m8 = " ".repeat(margin + 8);

    for t in rpdc {
        match t.typ {
            1 => println!("{_m2}NumBdirPorts: (Deprecated)"),
            2 => println!("{_m2}NumDsRfPorts: {}", to_u16(t.val)),
            3 => println!("{_m2}NumUsRfPorts: {}", to_u16(t.val)),
            4 => println!("{_m2}NumTenGeNsPorts: {}", to_u16(t.val)),
            5 => println!("{_m2}NumOneGeNsPorts: {}", to_u16(t.val)),
            6 => println!("{_m2}NumDsScQamChannels: {}", to_u16(t.val)),
            7 => println!("{_m2}NumDsOfdmChannels: {}", to_u16(t.val)),
            8 => println!("{_m2}NumUsScQamChannels: {}", to_u16(t.val)),
            9 => println!("{_m2}NumUsOfdmaChannels: {}", to_u16(t.val)),
            10 => println!("{_m2}NumDsOob55d1Channels: {}", to_u16(t.val)),
            11 => println!("{_m2}NumUsOob55d1Channels: {}", to_u16(t.val)),
            12 => println!("{_m2}NumOob55d2Modules: {}", to_u16(t.val)),
            13 => println!("{_m2}NumUsOob55d2Demodulators: {}", to_u16(t.val)),
            14 => println!("{_m2}NumNdfChannels: {}", to_u16(t.val)),
            15 => println!("{_m2}NumNdrChannels: {}", to_u16(t.val)),
            16 => {
                let sue = match tlv.val[0] {
                    0 => "(0) - The RPD does not support UDP encapsulation on L2TPv3 pseudowires."
                        .to_string(),
                    1 => "(1) - The RPD supports UDP encapsulation on L2TPv3 pseudowires."
                        .to_string(),
                    _ => "Unknown".to_string(),
                };
                println!("{_m2}SupportsUdpEncap: {}", sue);
            }
            17 => println!("{_m2}NumDsPspFlows: {}", t.val[0]),
            18 => println!("{_m2}NumUsPspFlows: {}", t.val[0]),
            19 => {
                println!("{_m2}RpdIdentification:");
                let (_, ri) = many1(parse_tlvs)(t.val).unwrap();

                for i in ri.iter() {
                    match i.typ {
                        1 => {
                            println!(
                                "{_m4}VendorName: {}",
                                str::from_utf8(i.val).unwrap().trim_end_matches('\0')
                            );
                        }
                        2 => {
                            println!("{_m4}VendorId: {}", to_u16(i.val));
                        }
                        3 => {
                            println!(
                                "{_m4}ModelNumber: {}",
                                str::from_utf8(i.val).unwrap().trim_end_matches('\0')
                            );
                        }
                        4 => {
                            println!(
                                "{_m4}DeviceMacAddress: {}",
                                MacAddress::from_bytes(i.val).unwrap().to_hex_string()
                            );
                        }
                        5 => {
                            println!(
                                "{_m4}CurrentSwVersion: {}",
                                str::from_utf8(i.val).unwrap().trim_end_matches('\0')
                            );
                        }

                        6 => {
                            println!(
                                "{_m4}BootRomVersion: {}",
                                str::from_utf8(i.val).unwrap().trim_end_matches('\0')
                            );
                        }

                        7 => {
                            println!(
                                "{_m4}DeviceDescription: {}",
                                str::from_utf8(i.val).unwrap().trim_end_matches('\0')
                            );
                        }
                        8 => {
                            println!(
                                "{_m4}DeviceAlias: {}",
                                str::from_utf8(i.val).unwrap().trim_end_matches('\0')
                            );
                        }
                        9 => {
                            println!(
                                "{_m4}SerialNumber: {}",
                                str::from_utf8(i.val).unwrap().trim_end_matches('\0')
                            );
                        }
                        10 => {
                            println!("{_m4}UsBurstReceiverVendorId: {}", to_u16(i.val));
                        }
                        11 => {
                            println!(
                                "{_m4}UsBurstReceiverModelNumber: {}",
                                str::from_utf8(i.val).unwrap().trim_end_matches('\0')
                            );
                        }
                        12 => {
                            println!(
                                "{_m4}UsBurstReceiverDriverVersion: {}",
                                str::from_utf8(i.val).unwrap().trim_end_matches('\0')
                            );
                        }
                        13 => {
                            println!(
                                "{_m4}UsBurstReceiverSerialNumber: {}",
                                str::from_utf8(i.val).unwrap().trim_end_matches('\0')
                            );
                        }
                        14 => {
                            println!(
                                "{_m4}RpdRcpProtocolVersion: {}",
                                str::from_utf8(i.val).unwrap().trim_end_matches('\0')
                            );
                        }
                        15 => {
                            println!(
                                "{_m4}RpdRcpSchemaVersion: {}",
                                str::from_utf8(i.val).unwrap().trim_end_matches('\0')
                            );
                        }
                        16 => {
                            println!(
                                "{_m4}HwRevision: {}",
                                str::from_utf8(i.val).unwrap().trim_end_matches('\0')
                            );
                        }
                        17 => {
                            println!(
                                "{_m4}AssetId: {}",
                                str::from_utf8(i.val).unwrap().trim_end_matches('\0')
                            );
                        }
                        18 => {
                            println!(
                                "{_m4}VspSelector: {}",
                                str::from_utf8(i.val).unwrap().trim_end_matches('\0')
                            );
                        }
                        19 => println!("{_m4}CurrentSwImageLastUpdate: {}", to_date_rfc2578(i)),
                        20 => {
                            println!(
                                "{_m4}CurrentSwImageName: {}",
                                str::from_utf8(i.val).unwrap().trim_end_matches('\0')
                            )
                        }
                        21 => {
                            if i.len == 4 {
                                println!("{_m4}CurrentSwImageServer: {}", to_ipv4(i.val));
                            } else if i.len == 16 {
                                println!("{_m4}CurrentSwImageServer: {}", to_ipv6(i.val));
                            } else {
                                println!(
                                    "{_m4}CurrentSwImageServer: Unable to format: {}:{:?}",
                                    i.len, i.val
                                );
                            }
                        }
                        22 => {
                            println!("{_m4}CurrrentSwImageIndex: {}", i.val[0]);
                        }
                        _ => {
                            println!(
                                "{_m4}Unknown RpdIdentification TLV type{}, Val:{:?}",
                                i.typ, i.val
                            );
                        }
                    };
                }
            }
            20 => {
                println!("{_m2}LcceChannelReachability:");
                let (_, le) = many1(parse_tlvs)(t.val).unwrap();

                for l in le.iter() {
                    match l.val[0] {
                        1 => println!("{_m4}EnetPortIndex: {}", l.val[0]),
                        2 => println!("{_m4}ChannelType: {}", RfChannelType(l.val[0])),
                        3 => println!("{_m4}RfPortIndex: {}", l.val[0]),
                        4 => println!("{_m4}StartChannelIndex: {}", l.val[0]),
                        5 => println!("{_m4}EndChannelIndex: {}", l.val[0]),
                        _ => println!("{_m4}Unknonw LcceChannelReachability Channel Type"),
                    };
                }
            }
            21 => {
                println!("{_m4}PilotToneCapabilities:");
                let (_, pt) = many1(parse_tlvs)(t.val).unwrap();

                for p in pt.iter() {
                    match p.typ {
                        //
                        1 => println!("{_m4}NumCwToneGens: {}", p.val[0]),
                        2 => println!("{_m4}LowestCwToneFreq:{}", to_u32(p.val)),
                        3 => println!("{_m4}HighestCwToneFreq:{}", to_u32(p.val)),
                        4 => println!("{_m4}MaxPowerDedCwTone:{}", to_u16(p.val)),
                        5 => {
                            let qa = match p.val[0] {
                                0 => "(0) - The RPD does not support configuration of QAM channels as CW tones.".to_string(),
                                1 => "(1) - The RPD supports configuration of QAM channels as CW tones.".to_string(),
                                _ => "Reserved".to_string(),
                            };
                            println!("{_m4}QamAsPilot:{}", qa);
                        }
                        6 => println!("{_m4}MinPowerDedCwTone:{}", to_u16(p.val)),
                        7 => println!("{_m4}MaxPowerQamCwTone:{}", to_u16(p.val)),
                        8 => println!("{_m4}MinPowerQamCwTone:{}", to_u16(p.val)),
                        _ => {
                            println!(
                                "{_m4}Unknown PilotToneCapabilities sub-TLV type:{}, val:{:?}",
                                p.typ, p.val
                            );
                        }
                    }
                }
            }
            22 => {
                println!("{_m2}AllocDsChanResources:");
                let (_, ad) = many1(parse_tlvs)(t.val).unwrap();

                for a in ad.iter() {
                    match a.typ {
                        1 => println!("{_m4}DsPortIndex: {}", a.val[0]),
                        2 => println!("{_m4}AllocatedDsOfdmChannels: {}", to_u16(a.val)),
                        3 => println!("{_m4}AllocatedDsScQamChannels: {}", to_u16(a.val)),
                        4 => println!("{_m4}AllocatedDsOob55d1Channels: {}", to_u16(a.val)),
                        5 => println!("{_m4}(Deprecated)"),
                        6 => println!("{_m4}AllocatedNdfChannels: {}", to_u16(a.val)),
                        7 => println!("{_m4}AllocatedBdrs: {}", to_u16(a.val)),
                        8 => println!("{_m4}ConfiguredBcgs: {}", to_u16(a.val)),
                        _ => println!("{_m4}Unknown AllocDsChanResources type."),
                    };
                }
            }
            23 => {
                println!("{_m2}AllocUSChanlResources:");
                let (_, au) = many1(parse_tlvs)(t.val).unwrap();

                for a in au.iter() {
                    match a.typ {
                        1 => println!("{_m4}UsPortIndex: {}", a.val[0]),
                        2 => println!("{_m4}AllocatedUsOfdmaChannels: {}", to_u16(a.val)),
                        3 => println!("{_m4}AllocatedUsScQamChannels: {}", to_u16(a.val)),
                        4 => println!("{_m4}AllocatedUsOob55d1Channels: {}", to_u16(a.val)),
                        5 => println!("{_m4}(Deprecated)"),
                        6 => println!("{_m4}AllocatedNdrChannels: {}", to_u16(a.val)),
                        _ => println!("{_m4}Unknown AllocUSChanlResources type."),
                    };
                }
            }
            24 => {
                println!("{_m2}DeviceLocation:");

                let _mar = margin + 2;
                let (_, dl) = many1(parse_tlvs)(t.val).unwrap();

                if dl.len() == 3 {
                    //
                    println!(
                        "{_m4}DeviceLocationDescription: {}",
                        str::from_utf8(dl[0].val).unwrap().trim_end_matches('\0')
                    );
                    println!(
                        "{_m4}GeoLocationLatitude: {}",
                        str::from_utf8(dl[1].val).unwrap().trim_end_matches('\0')
                    );
                    println!(
                        "{_m4}DeviceGeoLocationLongitude: {}",
                        str::from_utf8(dl[2].val).unwrap().trim_end_matches('\0')
                    );
                } else {
                    println!("{_m4}DeviceLocation is missing params");
                }
            }
            25 => println!("{_m2}NumAsyncVideoChannels: {}", t.val[0]),
            26 => {
                let respstr = match t.val[0] {
                    0 => "(0) - The RPD does not support Flow Tags.".to_string(),
                    1 => "(1) - The RPD supports FlowTags.".to_string(),
                    _ => "Reserved".to_string(),
                };
                println!("{_m2}SupportsFlowTags: {}", respstr);
            }
            27 => {
                let freq_tilt = match t.val[0] {
                    0 => "(0) - The RPD does not support Frequency Tilt settings.".to_string(),
                    1 => "(1) - The RPD supports Frequency Tilt settings.".to_string(),
                    _ => "Reserved".to_string(),
                };
                println!("{_m2}SupportsFrequencyTilt: {}", freq_tilt);
            }
            28 => {
                println!("{_m2}MaxTiltValue: {}", to_u16(t.val));
            }
            29 => {
                let value = t.val[0];
                println!("{_m2}BufferDepthMonitorAlertSupport: {value:#04X}",);
                let _s = format!("{value:08b}");
                println!("{_m4}{} {} ({value:#02X})", &_s[0..4], &_s[4..8]);
                println!("{_m4}{}", to_bitflags("OFDM channels", value.into(), 7, 8));
                println!(
                    "{_m4}{}",
                    to_bitflags("SC-QAM DOCSIS channels", value.into(), 6, 8)
                );
                println!(
                    "{_m4}{}",
                    to_bitflags("SC-QAM Video channels", value.into(), 5, 8)
                );
                println!("{_m4}{}", to_bitflags("NDF channels", value.into(), 4, 8));
                println!("{_m4}{}", to_bitflags("55-1 channels", value.into(), 3, 8));
                println!("{_m4}{}", to_bitflags("55-2 channels", value.into(), 2, 8));
                println!("{_m4}.... ...0 = Reserved");
            }
            30 => {
                let rep_str = match t.val[0] {
                    0 => "(0) - OFDM channels.".to_string(),
                    1 => "(1) - SC-QAM DOCSIS channels.".to_string(),
                    _ => "Reserved".to_string(),
                };
                println!("{_m2}BufferDepthConfigurationSupport: {}", rep_str);
            }
            31 => {
                println!(
                    "{_m2}RpdUcdProcessingTime: {} {}Seconds",
                    to_u16(t.val),
                    str::from_utf8(&SYM_MICRO).unwrap()
                );
            }
            32 => {
                println!(
                    "{_m2}RpdUcdChangeNullGrantTime: {} {}Seconds",
                    to_u16(t.val),
                    str::from_utf8(&SYM_MICRO).unwrap()
                );
            }
            33 => {
                let rep_str = match t.val[0] {
                    0 => "(0) - The RPD does not support Multi-Section Timing and MER Reporting.".to_string(),
                    1 => "(1) - The RPD supports equally spaced non-overlapping sections.".to_string(),
                    2 => "(2) - The RPD supports fully flexible sections and spacing of non-overlapping sections.".to_string(),
                    _ => "Reserved".to_string(),
                };
                println!("{_m2}SupportMultiSectionTimingMerReporting: {rep_str}");
            }
            34 => {
                println!("{_m2}RdtiCapabilities:");
                let (_, _tlvs) = many1(parse_tlvs)(t.val).unwrap();

                for a in _tlvs.iter() {
                    match a.typ {
                        1 => println!("{_m4}NumPtpPortsPerEnetPort: {}", a.val[0]),
                        _ => println!("{_m4}Unsupported RdtiCapabilities"),
                    };
                }
            }
            35 => println!("{_m2}MaxDsPspSegCount: {}", t.val[0]),
            36 => {
                let ret_str = match t.val[0] {
                    0 => "(0) - The RPD does not support optical node RF technology.".to_string(),
                    1 => "(1) - The RPD supports optical node RF technology.".to_string(),
                    _ => "Reserved".to_string(),
                };
                println!("{_m2}DirectDsFlowQueueMapping: {ret_str}");
            }
            37 => println!("{_m2}DsSchedulerPhbIdList: {}", HexFmt(t.val)),

            38 => println!("{_m2}RpdPendingEvRepQueueSize: {}", to_u16(t.val)),

            39 => println!("{_m2}RpdLocalEventLogSize: {}", to_u16(t.val)),

            40 => {
                let ret_str = match t.val[0] {
                    0 => "(0) - The RPD does not support optical node RF technology.".to_string(),
                    1 => "(1) - The RPD supports optical node RF technology.".to_string(),
                    _ => "Reserved".to_string(),
                };
                println!("{_m2}SupportsOpticalNodeRf: {ret_str}");
            }
            41 => println!("{_m2}MaxDsFrequency: {} Hertz", to_u16(t.val)),
            42 => println!("{_m2}MinDsFrequency: {} Hertz", to_u16(t.val)),
            43 => println!("{_m2}MaxBasePower: {} TenthdB", to_u16(t.val)),
            44 => println!("{_m2}MinTiltValue: {} TenthdB", to_u16(t.val)),
            45 => println!("{_m2}MinPowerAdjustScQam: {} TenthdB", to_u16(t.val)),
            46 => println!("{_m2}MaxPowerAdjustScQam: {} TenthdB", to_u16(t.val)),
            47 => println!("{_m2}MinPowerAdjustOfdm: {} TenthdB", to_u16(t.val)),
            48 => println!("{_m2}MaxPowerAdjustOfdm: {} TenthdB", to_u16(t.val)),
            49 => {
                println!("{_m2}UsPowerCapabilities:");
                let (_, tlvs) = many1(parse_tlvs)(t.val).unwrap();

                for t in tlvs.iter() {
                    match t.typ {
                        1 => println!(
                            "{_m4}MinBaseUsPowerTargetLevel: {} TenthdBmV per 1.6 MHz",
                            to_u16(t.val)
                        ),
                        2 => println!(
                            "{_m4}MaxBaseUsPowerTargetLevel: {} TenthdBmV per 1.6 MHz",
                            to_u16(t.val)
                        ),
                        3 => println!(
                            "{_m4}MinTargetRxPowerAdjustScqam: {} TenthdB",
                            to_u16(t.val)
                        ),
                        4 => println!(
                            "{_m4}MaxTargetRxPowerAdjustScqam: {} TenthdB",
                            to_u16(t.val)
                        ),
                        5 => println!(
                            "{_m4}MinTargetRxPowerAdjustOfdma: {} TenthdB",
                            to_u16(t.val)
                        ),
                        6 => println!(
                            "{_m4}MaxTargetRxPowerAdjustOfdma: {} TenthdB",
                            to_u16(t.val)
                        ),
                        7 => println!("{_m4}MinTargetRxPowerAdjustNdr: {} TenthdB", to_u16(t.val)),
                        8 => println!("{_m4}MaxTargetRxPowerAdjustNdr: {} TenthdB", to_u16(t.val)),
                        _ => println!("{_m4}Unknown UsPowerCapabilities sub-tlv"),
                    };
                }
            }
            50 => {
                let (_, tlvs) = many1(parse_tlvs)(t.val).unwrap();
                let _mar = margin + 2;

                println!("{_m2}StaticPwCapabilities:");
                for t in tlvs.iter() {
                    match t.typ {
                        1 => println!("{_m4}MaxFwdStaticPws: {}", to_u16(t.val)),

                        2 => println!("{_m4}MaxRetStaticPws: {}", to_u16(t.val)),

                        3 => {
                            let ret_str = match t.val[0] {
                                0 => "(0) - RPD does not support DEPI MPT static pseudowires."
                                    .to_string(),
                                1 => "(1) - RPD supports DEPI MPT static pseudowires.".to_string(),
                                _ => "Reserved".to_string(),
                            };
                            println!("{_m4}SupportsMptDepiPw: {}", ret_str);
                        }
                        4 => {
                            let ret_str = match t.val[0] {
                                0 => "(0) - RPD does not support SCTE 55-1 return static pseudowires. "
                                        .to_string(),
                                1 => "(1) - RPD supports SCTE 55-1 return static pseudowires."
                                    .to_string(),
                                _ => "Reserved".to_string(),
                            };
                            println!("{_m4}SupportsMpt55d1RetPw: {}", ret_str);
                        }
                        5 => {
                            let ret_str = match t.val[0] {
                                0 => "(0) - RPD does not support multicast PSP-NDF static pseudowires."
                                        .to_string(),
                                1 => "(1) - RPD supports multicast PSP-NDF static pseudowires."
                                    .to_string(),
                                _ => "Reserved".to_string(),
                            };
                            println!("{_m4}SupportsPspNdfMcastPw: {}", ret_str);
                        }
                        6 => {
                            let ret_str = match t.val[0] {
                                0 => "(0) - RPD does not support PSP-NDR static pseudowires."
                                    .to_string(),
                                1 => "(1) - RPD supports PSP-NDR static pseudowires.".to_string(),
                                _ => "Reserved".to_string(),
                            };
                            println!("{_m4}SupportsPspNdrPw: {}", ret_str);
                        }
                        7 => {
                            println!("{_m4}MaxUcastFwdStaticPws: {}", to_u16(t.val));
                        }
                        8 => {
                            let ret_str = match t.val[0] {
                                0 => "0 - RPD does not support unicast PSP-NDF static pseudowires."
                                    .to_string(),
                                1 => "1 - RPD supports unicast PSP-NDF static pseudowires."
                                    .to_string(),
                                _ => "Reserved".to_string(),
                            };
                            println!("{_m4}SupportsPspNdfUcastPw: {}", ret_str);
                        }
                        9 => {
                            let ret_str = match t.val[0] {
                                0 => "0 - RPD does not support PSP-PNM static pseudowires."
                                    .to_string(),
                                1 => "1 - RPD supports PSP-PNM static pseudowires.".to_string(),
                                _ => "Reserved".to_string(),
                            };
                            println!("{_m4}SupportsPspPnmPw: {}", ret_str);
                        }
                        10 => {
                            let ret_str = match t.val[0] {
                                0 => "0 - RPD does not support PSP-SPECMAN static pseudowires."
                                    .to_string(),
                                1 => "1 - RPD supports PSP-SPECMAN static pseudowires.".to_string(),
                                _ => "Reserved".to_string(),
                            };
                            println!("{_m4}SupportsPspSpecmanPw: {}", ret_str);
                        }
                        _ => {
                            println!("{_m4}Unsupported StaticPwCapabilities sub-TLV");
                        }
                    };
                }
            }
            51 => {
                println!("{_m2}DsCapabilities:");
                let (_, tlvs) = many1(parse_tlvs)(t.val).unwrap();

                for t in tlvs.iter() {
                    match t.typ {
                        1 => {
                            let value = to_u32(t.val);

                            println!("{_m4}DsScqamInterleaverSupport: {value:#04X}");
                            let _str = format!("{value:b}");
                            println!(
                                "{_m6}{} {} {} {} {} {} {} {} ({value:#04X})",
                                &_str[0..4],
                                &_str[4..8],
                                &_str[8..12],
                                &_str[12..16],
                                &_str[16..20],
                                &_str[20..24],
                                &_str[24..28],
                                &_str[28..32]
                            );
                            println!("{_m6}0... .... .... .... .... .... .... .... = Reserved");
                            println!("{_m6}{}", to_bitflags("taps8Increment16", value, 30, 32));
                            println!("{_m6}{}", to_bitflags("taps16Increment8", value, 29, 32));
                            println!("{_m6}{}", to_bitflags("taps32Increment4", value, 28, 32));
                            println!("{_m6}{}", to_bitflags("taps64Increment2", value, 27, 32));
                            println!("{_m6}{}", to_bitflags("taps128Increment1", value, 26, 32));
                            println!("{_m6}{}", to_bitflags("taps12increment17", value, 25, 32));
                            println!("{_m6}{}", to_bitflags("taps128Increment2", value, 24, 32));
                            println!("{_m6}{}", to_bitflags("taps128Increment3", value, 23, 32));
                            println!("{_m6}{}", to_bitflags("taps128Increment4", value, 22, 32));
                            println!("{_m6}{}", to_bitflags("taps128Increment5", value, 21, 32));
                            println!("{_m6}{}", to_bitflags("taps128Increment6", value, 20, 32));
                            println!("{_m6}{}", to_bitflags("taps128Increment7", value, 19, 32));
                            println!("{_m6}{}", to_bitflags("taps128Increment8", value, 18, 32));
                            println!("{_m6}.... .... .... ..00 0000 0000 0000 0000 = Reserved");
                        }
                        2 => println!("{_m4}DsMaxDocsisScQamChannels: {}", to_u16(t.val)),
                        3 => println!("{_m4}DsMaxMultipleScQamPspSessions: {}", to_u16(t.val)),
                        4 => println!("{_m4}NumBdrs: {}", to_u16(t.val)),
                        5 => println!("{_m4}NumBcgs: {}", to_u16(t.val)),
                        _ => println!("{_m4}Unsuported DsCapabilities sub-TLV."),
                    };
                }
            }
            52 => println!("{_m2}Type: {}, Value: {:?}", t.typ, t.val),
            53 => println!("{_m2}Type: {}, Value: {:?}", t.typ, t.val),
            54 => println!("{_m2}Type: {}, Value: {:?}", t.typ, t.val),
            55 => {
                println!("{_m2}ResetCapabilities:");

                let (_, tlvs) = many1(parse_tlvs)(t.val).unwrap();
                let _m = " ".repeat(margin + 2);
                for t in tlvs.iter() {
                    match t.typ {
                        1 => {
                            let _s = match t.val[0] {
                                0 => "(0) - RPD does not support softReset.".to_string(),
                                1 => "(1) - RPD supports softReset.".to_string(),
                                _ => "Reserved".to_string(),
                            };
                            println!("{_m4}SoftResetSupported: {_s}")
                        }
                        2 => {
                            let _s = match t.val[0] {
                                0 => "(0) - RPD does not support nvReset.".to_string(),
                                1 => "(1) - RPD supports nvReset.".to_string(),
                                _ => "Reserved".to_string(),
                            };
                            println!("{_m4}NvResetSupported: {_s}")
                        }
                        3 => {
                            let _s = match t.val[0] {
                                0 => "(0) - RPD does not support factoryReset.".to_string(),
                                1 => "(1) - RPD supports factoryReset.".to_string(),
                                _ => "Reserved".to_string(),
                            };
                            println!("{_m4}FactoryResetSupported: {_s}")
                        }
                        _ => println!("{_m4}Unsupported ResetCapabilities sub-type"),
                    };
                }
            }
            56 => println!("{_m2}Type: {}, Value: {:?}", t.typ, t.val),
            57 => println!("{_m2}Type: {}, Value: {:?}", t.typ, t.val),
            58 => println!("{_m2}Type: {}, Value: {:?}", t.typ, t.val),
            59 => {
                println!("{_m2}SpectrumCaptureCapabilities:");
                let (_, tlvs) = many1(parse_tlvs)(t.val).unwrap();

                for t in tlvs.iter() {
                    match t.typ {
                        1 => println!("{_m4}NumSacs: {}", t.val[0]),
                        2 => {
                            println!("{_m4}SacCapabilities:");
                            let (_, tlvs) = many1(parse_tlvs)(t.val).unwrap();
                            let _m = " ".repeat(margin + 4);
                            for t in tlvs.iter() {
                                match t.typ {
                                    1 => println!("{_m6}SacIndex: {}", t.val[0]),
                                    2 => println!(
                                        "{_m6}SacDescription: {}",
                                        str::from_utf8(t.val).unwrap().trim_end_matches('\0')
                                    ),
                                    3 => println!("{_m6}MaxCaptureSpan: {} hz", to_u16(t.val)),
                                    4 => println!(
                                        "{_m6}MinimumCaptureFrequency: {} hz",
                                        to_u16(t.val)
                                    ),
                                    5 => println!(
                                        "{_m6}MaximumCaptureFrequency: {} hz",
                                        to_u16(t.val)
                                    ),

                                    6 => {
                                        let value = to_u32(t.val);
                                        println!("{_m6}SupportedTriggerModes: {value:#010X}");
                                        let _s = format!("{value:032b}");
                                        println!(
                                            "{_m8}{} {} {} {} {} {} {} {} ({value:#010X})",
                                            &_s[0..4],
                                            &_s[4..8],
                                            &_s[8..12],
                                            &_s[12..16],
                                            &_s[16..20],
                                            &_s[20..24],
                                            &_s[24..28],
                                            &_s[28..32]
                                        );
                                        println!(
                                            "{_m8}{}",
                                            to_bitflags("freeRunning", value, 31, 32)
                                        );
                                        println!(
                                            "{_m8}{}",
                                            to_bitflags("miniSlotCount", value, 30, 32)
                                        );
                                        println!("{_m8}{}", to_bitflags("sid", value, 29, 32));
                                        println!("{_m8}{}", to_bitflags("not used", value, 28, 32));
                                        println!(
                                            "{_m8}{}",
                                            to_bitflags("quietProbeSymbol", value, 27, 32)
                                        );
                                        println!("{_m8}{}", to_bitflags("burstIuc", value, 26, 32));
                                        println!(
                                            "{_m8}{}",
                                            to_bitflags("timestamp", value, 25, 32)
                                        );
                                        println!(
                                            "{_m8}{}",
                                            to_bitflags("activeProbe", value, 24, 32)
                                        );
                                        println!("{_m8}.... .... 0000 0000 0000 0000 0000 0000 = Reserved");
                                    }
                                    7 => {
                                        let value = to_u32(t.val);
                                        println!("{_m6}SupportedOutputFormats: {value:#010X}");
                                        let _s = format!("{value:032b}");
                                        println!(
                                            "{_m8}{} {} {} {} {} {} {} {} ({value:#010X})",
                                            &_s[0..4],
                                            &_s[4..8],
                                            &_s[8..12],
                                            &_s[12..16],
                                            &_s[16..20],
                                            &_s[20..24],
                                            &_s[24..28],
                                            &_s[28..32]
                                        );
                                        println!("{_m8}{}", to_bitflags("timeIQ", value, 31, 32));
                                        println!("{_m8}{}", to_bitflags("fftPower", value, 30, 32));
                                        println!("{_m8}{}", to_bitflags("rawAdc", value, 29, 32));
                                        println!(
                                            "{_m8}{}",
                                            to_bitflags("fftIQ used", value, 28, 32)
                                        );
                                        println!(
                                            "{_m8}{}",
                                            to_bitflags("fftAmplitude", value, 27, 32)
                                        );
                                        println!("{_m8}{}", to_bitflags("fftDb", value, 26, 32));
                                        println!("{_m8}.... ..00 0000 0000 0000 0000 0000 0000 = Reserved");
                                    }
                                    8 => {
                                        let value = to_u32(t.val);
                                        println!("{_m6}SupportedWindowFormats: {value:#010X}");
                                        let _s = format!("{value:032b}");
                                        println!(
                                            "{_m8}{} {} {} {} {} {} {} {} ({value:#010X})",
                                            &_s[0..4],
                                            &_s[4..8],
                                            &_s[8..12],
                                            &_s[12..16],
                                            &_s[16..20],
                                            &_s[20..24],
                                            &_s[24..28],
                                            &_s[28..32]
                                        );
                                        println!(
                                            "{_m8}{}",
                                            to_bitflags("rectangular", value, 31, 32)
                                        );
                                        println!("{_m8}{}", to_bitflags("hann", value, 30, 32));
                                        println!(
                                            "{_m8}{}",
                                            to_bitflags("blackmanHarris", value, 29, 32)
                                        );
                                        println!("{_m8}{}", to_bitflags("hamming", value, 28, 32));
                                        println!("{_m8}{}", to_bitflags("flatTop", value, 27, 32));
                                        println!("{_m8}{}", to_bitflags("gaussian", value, 26, 32));
                                        println!(
                                            "{_m8}{}",
                                            to_bitflags("chebyshev", value, 25, 32)
                                        );
                                        println!("{_m8}.... ...0 0000 0000 0000 0000 0000 0000 = Reserved");
                                    }
                                    9 => {
                                        let _s = match t.val[0] {
                                            0 => {
                                                "(0) - SAC does not support averaging.".to_string()
                                            }
                                            1 => "(1) - SAC supports spectrum averaging.."
                                                .to_string(),
                                            _ => "Reserved".to_string(),
                                        };
                                        println!("{_m6}SupportsAveraging: {_s}")
                                    }
                                    10 => println!(
                                        "{_m6}SupportedAggregationMethods: {}",
                                        to_u16(t.val)
                                    ),
                                    11 => {
                                        let _s = match t.val[0] {
                                            0 => "(0) - SAC does not support spectrum qualification feature".to_string(),
                                            1 => "(1) - SAC supports spectrum qualification feature.".to_string(),
                                            _ => "Reserved".to_string(),
                                        };
                                        println!("{_m6}SupportsSpectrumQualification: {_s}")
                                    }
                                    12 => println!("{_m6}MaxNumBins: {}", to_u16(t.val)),
                                    13 => println!("{_m6}MinNumBins: {}", to_u16(t.val)),
                                    14 => println!(
                                        "{_m6}MinRepeatPeriod: {} microseconds",
                                        to_u16(t.val)
                                    ),
                                    15 => {
                                        let _s = match t.val[0] {
                                            0 => "(0) - SC-QAM channel.".to_string(),
                                            1 => "(1) - OFDMA channel.".to_string(),
                                            _ => "Reserved".to_string(),
                                        };
                                        println!("{_m6}SupportedTrigChanTypes: {_s}");
                                    }
                                    16 => {
                                        let _s = match t.val[0] {
                                            0 => "(0) - PNM PW.".to_string(),
                                            1 => "(1) - SpecMan PW.".to_string(),
                                            _ => "Reserved".to_string(),
                                        };
                                        println!("{_m6}PwType: {_s}");
                                    }
                                    17 => {
                                        println!("{_m6}LowestCapturePort: {}", t.val[0]);
                                    }
                                    18 => {
                                        println!("{_m6}HighestCapturePort: {}", t.val[0]);
                                    }
                                    19 => {
                                        let _s = match t.val[0] {
                                            0 => {
                                                "(0) - SAC does not support Port Scanning Capture."
                                                    .to_string()
                                            }
                                            1 => "(1) - SAC supports Port Scanning Capture."
                                                .to_string(),
                                            _ => "Reserved".to_string(),
                                        };
                                        println!("{_m6}SupportsScanningCapture: {_s}")
                                    }
                                    20 => {
                                        println!("{_m6}MinScanningRepeatPeriod: {}", to_u16(t.val));
                                    }
                                    _ => println!("{_m6}Unsupported SacCapabilities sub-type"),
                                };
                            }
                        }
                        _ => println!("{_m4}Unsupported SpectrumCaptureCapabilities sub-type"),
                    };
                }
            }
            60 => {
                println!("{_m2}RfmCapabilities:");
                let (_, tlvs) = many1(parse_tlvs)(t.val).unwrap();
                for t in tlvs.iter() {
                    match t.typ {
                        1 => {
                            let _s = match t.val[0] {
                                0 => "(0) - The RPD does not support RFM management.".to_string(),
                                1 => "(1) - The RPD supports RFM management.".to_string(),
                                _ => "Reserved".to_string(),
                            };
                            println!("{_m4}SupportsRfmManagement: {_s}")
                        }
                        2 => println!("{_m4}NumNodeRfPorts: {}", to_u16(t.val)),
                        3 => {
                            let _s = match t.val[0] {
                                0 => "(0) - The RPD does not support GCP configuration of the DS RFM power gain.".to_string(),
                                1 => "(1) - The RPD supports GCP configuration of the DS RFM power gain.".to_string(),
                                _ => "Reserved".to_string(),
                            };
                            println!("{_m4}SupportsDsCfgRfmGain: {_s}");
                        }
                        4 => println!("{_m4}MinDsCfgRfmGain: {}", to_u16(t.val)),
                        5 => println!("{_m4}MaxDsCfgRfmGain: {}", to_u16(t.val)),
                        6 => {
                            let _s = match t.val[0] {
                                0 => "(0) - The RPD does not support GCP configuration of the US RFM gain.".to_string(),
                                1 => "(1) - The RPD supports GCP configuration of the US RFM gain.".to_string(),
                                _ => "Reserved".to_string(),
                            };
                            println!("{_m4}SupportsUsCfgRfmGain: {_s}");
                        }
                        7 => println!("{_m4}MinUsCfgRfmGain: {}", to_u16(t.val)),
                        8 => println!("{_m4}MaxUsCfgRfmGain: {}", to_u16(t.val)),
                        9 => {
                            let _s = match t.val[0] {
                                0 => "(0) - The RPD does not support GCP configuration of the RFM DS tilt.".to_string(),
                                1 => "(1) - The RPD supports GCP configuration of the RFM DS tilt.".to_string(),
                                _ => "Reserved".to_string(),
                            };
                            println!("{_m4}SupportsRfmDsTiltConfig: {_s}")
                        }
                        10 => println!("{_m4}MinRfmDsTilt: {}", to_u16(t.val)),
                        11 => println!("{_m4}MaxRfmDsTilt: {}", to_u16(t.val)),
                        12 => println!("{_m4}MaxDsPowerGainFunctions: {}", to_u16(t.val)),
                        13 => println!("{_m4}MaxUsPowerGainFunctions: {}", to_u16(t.val)),
                        14 => println!("{_m4}MaxDsTiltCtrlFunctions: {}", to_u16(t.val)),
                        15 => println!("{_m4}MinRfmDsFreq: {}", to_u32(t.val)),
                        16 => println!("{_m4}MaxRfmDsFreq: {}", to_u32(t.val)),
                        17 => {
                            println!("{_m4}NodeRfPortCapabilities:");
                            let (_, tlvs) = many1(parse_tlvs)(t.val).unwrap();
                            for t in tlvs.iter() {
                                match t.typ {
                                    1 => println!("{_m6}NodeRfPortIndex: {}", t.val[0]),
                                    2 => println!(
                                        "{_m6}NodeRfPortManufDesc: {}",
                                        str::from_utf8(t.val).unwrap().trim_end_matches('\0')
                                    ),
                                    3 => println!("{_m6}RpdUsRfPortMap: {}", t.val[0]),
                                    4 => println!("{_m6}RpdDsRfPortMap: {}", t.val[0]),
                                    5 => println!("{_m6}RfmUsGainCtrlIndex: {}", t.val[0]),
                                    6 => println!("{_m6}RfmDsGainCtrlIndex: {}", t.val[0]),
                                    7 => println!("{_m6}RfmDsTiltCtrlIndex: {}", t.val[0]),
                                    8 => println!(
                                        "{_m6}NodeRfPortOperatorLabel: {}",
                                        str::from_utf8(t.val).unwrap().trim_end_matches('\0')
                                    ),
                                    _ => {
                                        println!("{_m6}Unsupported NodeRfPortCapabilities sub-type")
                                    }
                                };
                            }
                        }
                        _ => println!("{_m4}Unsupported RfmCapabilities sub-type"),
                    };
                }
            }
            61 => {
                println!("{_m2}UpstreamCapabilities:");
                let (_, tlvs) = many1(parse_tlvs)(t.val).unwrap();
                for t in tlvs.iter() {
                    match t.typ {
                        1 => println!("{_m4}MaxUsFrequency: {}", to_u32(t.val)),
                        2 => println!("{_m4}MinUsFrequency: {}", to_u32(t.val)),
                        3 => println!("{_m4}MaxUnicastSids: {}", to_u16(t.val)),
                        _ => println!("{_m4}Unsupported UpstreamCapabilities sub-type"),
                    };
                }
            }
            62 => {
                println!("{_m2}PmtudCapabilities:");
                let (_, tlvs) = many1(parse_tlvs)(t.val).unwrap();
                let _m = " ".repeat(margin + 2);
                for t in tlvs.iter() {
                    match t.typ {
                        1 => {
                            let _s = match t.val[0] {
                                0 => "(0) - The RPD does not support PMTUD based on these RFCs."
                                    .to_string(),
                                1 => {
                                    "(1) - The RPD supports PMTUD based on these RFCs.".to_string()
                                }
                                _ => "Reserved".to_string(),
                            };
                            println!("{_m4}SupportsIcmpBasedPmtud: {_s}");
                        }
                        2 => {
                            let _s = match t.val[0] {
                                0 => "(0) - The RPD does not support PMTUD based on RFC4821."
                                    .to_string(),
                                1 => "(1) - The RPD supports PMTUD based on RFC4821.".to_string(),
                                _ => "Reserved".to_string(),
                            };
                            println!("{_m4}SupportsPacketizationBasedPmtud: {_s}");
                        }
                        _ => println!("{_m4}Unsupported PmtudCapabilities sub-type"),
                    };
                }
            }
            63 => {
                let _s = match t.val[0] {
                    0 => "(0) - The RPD does not support the FlowTagIncrement TLV.".to_string(),
                    1 => "(1) - The RPD supports the FlowTagIncrement TLV.".to_string(),
                    _ => "Reserved".to_string(),
                };
                println!("{_m2}SupportsFlowTagIncrement: {_s}");
            }
            _ => {
                println!(
                    "{_m2}Unknown RpdCapability TLV type:{}, Val:{:?}",
                    t.typ, t.val
                );
            }
        }
    }
}

fn complex_tlv_dsrfport(tlv: &RphyTlv, margin: usize) {
    //
    let (_, tlvs) = many1(parse_tlvs)(tlv.val).unwrap();
    let _m = " ".repeat(margin);
    let _m2 = " ".repeat(margin + 2);
    for t in tlvs.iter() {
        match t.typ {
            2 => println!("{_m}AdminState: {}", AdminStateType(t.val[0])),
            3 => println!("{_m}BasePower: {} TenthdBmV per 6MHz.", to_u16(t.val)),
            4 => {
                let _s = match t.val[0] {
                    0 => "(0) - Port is not muted.".to_string(),
                    1 => "(1) - Port is muted.".to_string(),
                    _ => "Reserved".to_string(),
                };
                println!("{_m}RfMute: {_s}");
            }
            5 => println!("{_m}TiltValue: {} TenthdB.", to_u16(t.val)),
            6 => println!("{_m}TiltMaximumFrequency: {} Hertz", to_u32(t.val)),
            7 => {
                let (_, tlvs) = many1(parse_tlvs)(t.val).unwrap();
                println!("{_m}DedicatedToneConfig:");
                for p in tlvs.iter() {
                    match p.typ {
                        1 => println!("{_m2}ToneIndex: {}", p.val[0]),
                        2 => println!("{_m2}ToneFrequency: {} Hertz.", to_u32(p.val)),
                        3 => println!("{_m2}TonePowerAdjust: {}", to_u16(p.val)),
                        4 => {
                            let _s = match p.val[0] {
                                0 => "(0) - Generator is not muted.".to_string(),
                                1 => "(1) - Generator is muted.".to_string(),
                                _ => "Reserved".to_string(),
                            };
                            println!("{_m2}RfMute: {_s}");
                        }
                        5 => println!("{_m2}FrequencyFraction: {} TenthHz.", p.val[0]),
                        _ => println!("{_m2}Unsupported name sub-type"),
                    };
                }
            }
            8 => println!("{_m}FdxAllocSpectrumWidth: {}", to_u16(t.val)),
            _ => println!("{_m}Unsupported DsRfPort sub-type"),
        };
    }
}

fn complex_tlv_dsscqamchannelconfig(tlv: &RphyTlv, margin: usize) {
    //
    let (_, tlvs) = many1(parse_tlvs)(tlv.val).unwrap();
    let _m = " ".repeat(margin);
    for t in tlvs.iter() {
        match t.typ {
            1 => println!("{_m}AdminState: {}", AdminStateType(t.val[0])),
            2 => println!("{_m}CcapCoreOwner: {}", HexFmt(t.val)),
            3 => {
                let _s = match t.val[0] {
                    0 => "(0) - Channel is not muted.".to_string(),
                    1 => "(1) - Channel is muted.".to_string(),
                    _ => "Reserved".to_string(),
                };
                println!("{_m}RfMute: {_s}");
            }
            4 => println!("{_m}TSID: {}", to_u16(t.val)),
            5 => println!("{_m}CenterFrequency: {} Hertz", to_u16(t.val)),
            6 => println!("{_m}OperationaMode: {}", OperationalMode(t.val[0])),
            7 => println!("{_m}Modulation: {}", DsModulationType(t.val[0])),
            8 => println!("{_m}InterleaverDepth: {}", InterleaverDepth(t.val[0])),
            9 => println!("{_m}Annex: {}", DsInterleaverType(t.val[0])),
            10 => println!("{_m}SyncInterval: {} Milliseconds.", t.val[0]),
            11 => println!(
                "{_m}SyncMacAddress: {}",
                MacAddress::from_bytes(t.val).unwrap().to_hex_string()
            ),
            12 => println!("{_m}SymbolFrequencyDenominator: {}", to_u16(t.val)),
            13 => println!("{_m}SymbolFrequencyNumerator: {}", to_u16(t.val)),
            14 => println!("{_m}SymbolRateOverride: {}", to_u32(t.val)),
            15 => {
                let _s = match t.val[0] {
                    0 => "(0) - Channel's spectrum is not inverted.".to_string(),
                    1 => "(1) - Channel's spectrum is inverted.".to_string(),
                    _ => "Reserved".to_string(),
                };
                println!("{_m}SpectrumInversionEnabled: {_s}");
            }
            16 => println!("{_m}PowerAdjust: {} TenthdB", to_u16(t.val)),
            17 => {
                let _s = match t.val[0] {
                    0 => "(0) - Channel is not incldued in a BCG.".to_string(),
                    1 => "(1) - Channel is included in a BCG.".to_string(),
                    _ => "Reserved".to_string(),
                };
                println!("{_m}BcastChanGroup: {_s}");
            }

            _ => println!("{_m}Unsupported name sub-type"),
        };
    }
}

fn complex_tlv_dsofdmchannelconfig(tlv: &RphyTlv, margin: usize) {
    let (_, tlvs) = many1(parse_tlvs)(tlv.val).unwrap();
    let _m = " ".repeat(margin);
    let _m2 = " ".repeat(margin + 2);

    for t in tlvs.iter() {
        match t.typ {
            1 => println!("{_m}AdminState: {}", AdminStateType(t.val[0])),
            2 => println!("{_m}CcapCoreOwner: {}", HexFmt(t.val)),
            3 => {
                let _s = match t.val[0] {
                    0 => "(0) - Channel is not muted.".to_string(),
                    1 => "(1) - Channel is muted.".to_string(),
                    _ => "Reserved".to_string(),
                };
                println!("{_m}RfMute: {_s}");
            }
            4 => println!("{_m}SubcarrierZeroFreq: {} Hertz", to_u32(t.val)),
            5 => println!("{_m}FirstActiveSubcarrier: {}", to_u16(t.val)),
            6 => println!("{_m}LastActiveSubcarrier: {}", to_u16(t.val)),
            7 => println!("{_m}NumActiveSubcarriers: {}", to_u16(t.val)),
            8 => println!("{_m}CyclicPrefix: {}", CyclicPrefix(t.val[0])),
            9 => println!("{_m}RollOffPeriod: {}", RollOffPeriodType(t.val[0])),
            10 => println!("{_m}PlcFreq: {} Hertz", to_u32(t.val)),
            11 => println!("{_m}TimeInterleaverDepth: {}", t.val[0]),
            12 => {
                let _s = match t.val[0] {
                    1 => "(1) - Subcarrier spacing of 25 KHz.".to_string(),
                    2 => "(2) - Subcarrier spacing of 50 KHz.".to_string(),
                    _ => "Reserved".to_string(),
                };
                println!("{_m}SubcarrierSpacing: {_s}");
            }
            13 => {
                //
                let (_, tlvs) = many1(parse_tlvs)(t.val).unwrap();
                println!("{_m}DsOfdmSubcarrierType:");
                for a in tlvs.iter() {
                    match t.typ {
                        1 => println!("{_m2}StartSubcarrierId: {}", to_u16(a.val)),
                        2 => println!("{_m2}EndSubcarrierId: {}", to_u16(a.val)),
                        3 => println!("{_m2}SubcarrierUsage: {}", SubcarrierUsage(a.val[0])),
                        _ => println!("{_m2}Unsuported DsOfdmSubcarrierType sub-type"),
                    }
                }
            }
            14 => println!("{_m}PowerAdjust: {}", to_u16(t.val)),
            _ => println!("{_m}Unsupported name sub-type"),
        };
    }
}

fn complex_tlv_dsofdmprofile(tlv: &RphyTlv, margin: usize) {
    let (_, tlvs) = many1(parse_tlvs)(tlv.val).unwrap();
    let _m = " ".repeat(margin);
    let _m2 = " ".repeat(margin + 2);
    for t in tlvs.iter() {
        match t.typ {
            1 => println!("{_m}ProfileId: {}", t.val[0]),
            2 => {
                println!("{_m}DsOfdmSubcarrierModulation:");
                let (_, tlvs) = many1(parse_tlvs)(tlv.val).unwrap();
                for a in tlvs.iter() {
                    match a.typ {
                        1 => println!("{_m2}StartSubcarrierId: {}", to_u16(a.val)),
                        2 => println!("{_m2}EndSubcarrierId: {}", to_u16(a.val)),
                        3 => println!("{_m2}Modulation: {}", DsOfdmModulationType(a.val[0])),
                        _ => println!("{_m2}Reserved"),
                    };
                }
            }
            _ => println!("{_m}Unsupported DsOfdmProfile sub-type"),
        };
    }
}

fn complex_tlv_usscqamchannelconfig(tlv: &RphyTlv, margin: usize) {
    //

    let (_, tlvs) = many1(parse_tlvs)(tlv.val).unwrap();
    let _m = " ".repeat(margin);
    let _m2 = " ".repeat(margin + 2);
    for t in tlvs.iter() {
        match t.typ {
            1 => println!("{_m}AdminState: {}", AdminStateType(t.val[0])),
            2 => println!("{_m}CcapCoreOwner: {:X}", HexFmt(t.val)),
            3 => println!("{_m}ChannelType: {}", UpstreamChannelType(t.val[0])),
            4 => println!("{_m}CenterFrequency: {} Hertz", to_u32(t.val)),
            5 => println!("{_m}Width: {} Hertz", to_u32(t.val)),
            6 => println!("{_m}SlotSize: {} (6.25 usec tics)", to_u32(t.val)),
            7 => println!("{_m}StartingMinislot: {}", to_u32(t.val)),
            8 => println!("{_m}PreambleString: {:X}", HexFmt(t.val)),
            9 => println!("{_m}TargetRxPowerAdjust: {} TenthdB", to_u16(t.val)),
            10 => {
                println!("{_m}IntervalUsageCode:");
                let (_, tlvs) = many1(parse_tlvs)(t.val).unwrap();
                for u in tlvs.iter() {
                    match u.typ {
                        1 => println!("{_m2}Code: {}", u.val[0]),
                        2 => {
                            let _s = match t.val[0] {
                                0 => "(0) - Differential Encoding is off.".to_string(),
                                1 => "(1) - Differential Encoding is on.".to_string(),
                                _ => "Reserved".to_string(),
                            };
                            println!("{_m2}DifferentialEncoding: {_s}");
                        }
                        3 => {
                            println!("{_m2}FecErrorCorrectionT: {}", u.val[0]);
                        }
                        4 => println!("{_m2}FecCodewordLength: {} bytes", u.val[0]),
                        5 => println!("{_m2}PreambleLen: {} bits", to_u16(u.val)),
                        6 => println!("{_m2}PreambleOffsett: {} bits", to_u16(u.val)),
                        7 => {
                            let _s = match t.val[0] {
                                1 => "(1) - QPSK0".to_string(),
                                2 => "(2) - QPSK1".to_string(),
                                _ => "Reserved".to_string(),
                            };
                            println!("{_m2}PreambleModType: {_s}");
                        }
                        8 => {
                            let _s = match t.val[0] {
                                0 => "(0) - Scrambler is off.".to_string(),
                                1 => "(1) - Scrambler is on.".to_string(),
                                _ => "Reserved".to_string(),
                            };
                            println!("{_m2}Scrambler: {_s}");
                        }
                        9 => println!("{_m2}ScrambleSeed: {}", to_u16(u.val)),
                        10 => println!("{_m2}MaxBurstSize: {}", u.val[0]),
                        11 => {
                            let _s = match t.val[0] {
                                0 => "(0) - last codeword is fixed (not shortened).".to_string(),
                                1 => "(1) - last codeword is shortened.".to_string(),
                                _ => "Reserved".to_string(),
                            };
                            println!("{_m2}LasCodewordShortened: {_s}");
                        }
                        12 => {
                            let _s = match t.val[0] {
                                0 => "(0) indicates Dynamic mode.".to_string(),
                                1 => "(1) indicates R-S interleaving is disabled.".to_string(),
                                _ => "Reserved".to_string(),
                            };
                            println!("{_m2}ByteInterleaverDepth: {_s}");
                        }
                        13 => println!("{_m2}ByteInterleaverBlockSize: {}", to_u16(u.val)),
                        14 => println!("{_m2}ModulationType: {}", UpstreamModulationType(u.val[0])),
                        15 => println!("{_m2}GuardTime: {}", u.val[0]),
                        _ => println!("{_m2}Unsupported name sub-type"),
                    };
                }
            }
            11 => {
                let _s = match t.val[0] {
                    0 => "(0) - Sending of EQ coefficient is suppressed.".to_string(),
                    1 => "(1) - Sending of EQ coefficient is not suppressed.".to_string(),
                    _ => "Reserved".to_string(),
                };
                println!("{_m}EqualizationCoeffEnable: {_s}");
            }
            12 => {
                let _s = match t.val[0] {
                    0 => "(0) - Ingress noise cancellation is not enabled.".to_string(),
                    1 => "(1) - Ingress noise cancellation is enabled.".to_string(),
                    _ => "Reserved".to_string(),
                };
                println!("{_m}IngressNoiseCancelEnable: {_s}");
            }
            13 => println!("{_m}UsChanId: {}", t.val[0]),
            14 => println!("{_m}ConfigChangeCount: {}", t.val[0]),
            15 => println!("{_m}DsChanId: {}", t.val[0]),
            _ => println!("{_m}Unsupported name sub-type"),
        };
    }
}

fn complex_tlv_staticpwconfig(tlv: &RphyTlv, margin: usize) {
    let (_, tlvs) = many1(parse_tlvs)(tlv.val).unwrap();
    let _m = " ".repeat(margin);
    let _m2 = " ".repeat(margin + 2);
    let _m4 = " ".repeat(margin + 4);
    let _m6 = " ".repeat(margin + 6);
    for t in tlvs.iter() {
        match t.typ {
            1 => {
                println!("{_m}FwdStaticPwConfig:");
                let (_, tlvs) = many1(parse_tlvs)(t.val).unwrap();
                for t in tlvs.iter() {
                    match t.typ {
                        1 => println!("{_m2}Index: {}", to_u16(t.val)),
                        2 => println!("{_m2}CcapCoreOwner: {:X}", HexFmt(t.val)),
                        3 => {
                            if t.len == 16 {
                                println!("{_m2}GroupAddress: {}", to_ipv6(t.val));
                            } else if t.len == 4 {
                                println!("{_m2}GroupAddress: {}", to_ipv4(t.val));
                            } else {
                                println!("{_m2}GroupAddress: Invalid lenght.");
                            }
                        }
                        4 => {
                            if t.len == 16 {
                                println!("{_m2}SourceAddress: {}", to_ipv6(t.val));
                            } else if t.len == 4 {
                                println!("{_m2}SourceAddress: {}", to_ipv4(t.val));
                            } else {
                                println!("{_m2}SourceAddress: Invalid lenght.");
                            }
                        }
                        5 => {
                            let _s = match t.val[0] {
                                0 => "(0) - The pseudowire is multicast static pseudowire."
                                    .to_string(),
                                1 => {
                                    "(1) - The pseudowire is unicast static pseudowire.".to_string()
                                }
                                _ => "Reserved".to_string(),
                            };
                            println!("{_m2}IsUnicast: {_s}");
                        }
                        _ => println!("{_m}Unsupported FwdStaticPwConfig sub-type"),
                    };
                }
            }
            2 => {
                println!("{_m}RetStaticPwConfig:");
                let (_, tlvs) = many1(parse_tlvs)(t.val).unwrap();
                for t in tlvs.iter() {
                    match t.typ {
                        1 => println!("{_m2}Index: {}", to_u16(t.val)),
                        2 => println!("{_m2}CcapCoreOwner: {:X}", HexFmt(t.val)),
                        3 => {
                            if t.len == 16 {
                                println!("{_m2}DestAddress: {}", to_ipv6(t.val));
                            } else if t.len == 4 {
                                println!("{_m2}DestAddress: {}", to_ipv4(t.val));
                            } else {
                                println!("{_m2}DestAddress: Invalid lenght.");
                            }
                        }
                        4 => println!("{_m2}MtuSize: {}", to_u16(t.val)),
                        5 => println!("{_m2}UsPhbId: {}", t.val[0]),
                        _ => println!("{_m}Unsupported RetStaticPwConfig sub-type"),
                    };
                }
            }
            3 => {
                println!("{_m}CommonStaticPwConfig:");
                let (_, tlvs) = many1(parse_tlvs)(t.val).unwrap();
                for t in tlvs.iter() {
                    match t.typ {
                        1 => println!("{_m2}Direction: {}", t.val[0]),
                        2 => println!("{_m2}Index: {}", to_u16(t.val)),
                        4 => println!("{_m2}PwType: {}", PwType(to_u16(t.val))),
                        5 => println!("{_m2}DepiPwSubtype: {}", DepiPwSubtype(to_u16(t.val))),
                        6 => println!("{_m2}L2SublayerType: {}", L2SublayerType(to_u16(t.val))),
                        7 => println!(
                            "{_m2}DepiL2SublayerSubtype: {}",
                            L2SublayerSubType(to_u16(t.val))
                        ),
                        8 => println!("{_m2}SessionId: {}", to_u32(t.val)),
                        9 => {
                            let value = to_u16(t.val);
                            println!("{_m2}CircuitStatus: {value:#06X}");
                            let _s = format!("{value:016b}");
                            println!(
                                "{_m4}{} {} {} {} ({value:#04X})",
                                &_s[0..4],
                                &_s[4..8],
                                &_s[8..12],
                                &_s[12..16]
                            );
                            println!("{_m4}{}", to_bitflags("A bit", value.into(), 15, 16));
                            println!("{_m4}{}", to_bitflags("N bit", value.into(), 14, 16));
                            println!("{_m4}..00 0000 0000 0000 = Reserved");
                        }
                        10 => println!("{_m2}RpdEnetPortIndex: {}", t.val[0]),
                        11 => {
                            println!("{_m2}PwAssociation:");
                            let (_, tlvs) = many1(parse_tlvs)(t.val).unwrap();
                            for t in tlvs.iter() {
                                match t.typ {
                                    1 => println!("{_m4}Index: {}", t.val[0]),
                                    2 => {
                                        println!("{_m4}ChannelSelector:");
                                        let (_, tlvs) = many1(parse_tlvs)(t.val).unwrap();
                                        for c in tlvs.iter() {
                                            match c.typ {
                                                1 => println!("{_m6}RfPortIndex: {}", c.val[0]),
                                                2 => println!(
                                                    "{_m6}ChannelType: {}",
                                                    ChannelType(c.val[0])
                                                ),
                                                3 => println!("{_m6}ChannelIndex: {}", c.val[0]),
                                                _ => println!(
                                                    "{_m6}Unsupported ChannelSelector sub-type"
                                                ),
                                            };
                                        }
                                    }
                                    _ => println!("{_m}Unsupported PwAssociation sub-type"),
                                };
                            }
                        }
                        12 => {
                            let _s =
                                match t.val[0] {
                                    0 => "(0) - RpdCircuitStatus notifications are disabled."
                                        .to_string(),
                                    1 => "(1) - RpdCircuitStatus notifications are enabled."
                                        .to_string(),
                                    _ => "Reserved".to_string(),
                                };
                            println!("{_m2}EnableStatusNotification: {_s}");
                        }
                        _ => println!("{_m}Unsupported CommonStaticPwConfig sub-type"),
                    };
                }
            }
            _ => println!("{_m}Unsupported StaticPwConfig sub-type"),
        };
    }
}

fn complex_tlv_rpdstate(tlv: &RphyTlv, margin: usize) {
    println!("{}RpdState:", " ".repeat(margin));
    let (_, tlvs) = many1(parse_tlvs)(tlv.val).unwrap();
    let _m = " ".repeat(margin);
    let _m2 = " ".repeat(margin + 2);
    for t in tlvs.iter() {
        match t.typ {
            1 => println!("{_m}TopLevelRpdstate: {}", TopLevelRpdstate(t.val[0])),
            2 => {
                println!("{_m}NetworkAuthenticationState:");

                let (_, tlvs) = many1(parse_tlvs)(t.val).unwrap();
                for t in tlvs.iter() {
                    match t.typ {
                        1 => println!("{_m2}NetworkAuthenticationPortIndex: {}", t.val[0]),
                        2 => println!(
                            "{_m2}NetworkAuthenticationRpdState: {}",
                            NetworkAuthenticationRpdState(t.val[0])
                        ),
                        _ => println!("{_m}Unsupported name sub-type"),
                    };
                }
            }
            3 => println!(
                "{_m}ConnectPrincipalCoreSubState: {}",
                CoreSubState(t.val[0])
            ),
            4 => {
                println!("{_m}AuxCoreState::");

                let (_, tlvs) = many1(parse_tlvs)(t.val).unwrap();
                for t in tlvs.iter() {
                    match t.typ {
                        1 => println!("{_m2}AuxCoreIndex: {}", t.val[0]),
                        2 => println!("{_m2}AusCoreId: {}", HexFmt(t.val)),
                        3 => {
                            if t.len == 16 {
                                println!("{_m2}AuxCoreIp: {}", to_ipv6(t.val));
                            } else if t.len == 4 {
                                println!("{_m2}AuxCoreIp: {}", to_ipv4(t.val));
                            } else {
                                println!("{_m2}AuxCoreIp: Invalid lenght.");
                            }
                        }
                        4 => println!("{_m2}CoreSubState: {}", CoreSubState(t.val[0])),
                        _ => println!("{_m}Unsupported name sub-type"),
                    };
                }
            }
            5 => {
                if t.len == 0 {
                    println!("{_m}LocalPtpSyncStatus: Length of TLV is 0 and no value. <-- Something wrong?");
                } else {
                    let _s = match t.val[0] {
                        0 => "(0) - RPD has not achieved PTP synchronization".to_string(),
                        1 => "(1) - RPD has achieved PTP synchronization".to_string(),
                        _ => "Reserved".to_string(),
                    };
                    println!("{_m}LocalPtpSyncStatus: {_s}");
                }
            }
            _ => println!("{_m}Unsupported RpdState sub-type"),
        };
    }
}

fn complex_tlv_usofdmachannelconfig(tlv: &RphyTlv, margin: usize) {
    let (_, tlvs) = many1(parse_tlvs)(tlv.val).unwrap();
    let _m = " ".repeat(margin);
    let _m2 = " ".repeat(margin + 2);
    for t in tlvs.iter() {
        match t.typ {
            1 => println!("{_m}AdminState: {}", AdminStateType(t.val[0])),
            2 => println!("{_m}CcapCoreOwner: {:X}", HexFmt(t.val)),
            3 => println!("{_m}SubcarrierZeroFreq: {}", to_u32(t.val)),
            4 => println!("{_m}FirstActiveSubcarrierNum: {}", to_u16(t.val)),
            5 => println!("{_m}LastActiveSubcarrierNum: {}", to_u16(t.val)),
            6 => println!(
                "{_m}RollOffPeriod: {}",
                UsOfdmaRollOffPeriodType(to_u16(t.val))
            ),
            7 => println!(
                "{_m}CyclicPrefix: {}",
                UsOfdmaCyclicPrefixType(to_u16(t.val))
            ),
            8 => println!("{_m}SubcarrierSpacing: {}", SubcarrierSpacingType(t.val[0])),
            9 => println!("{_m}NumSymbolsPerFrame: {}", t.val[0]),
            10 => println!("{_m}NumActiveSubcarriers: {}", to_u16(t.val)),
            11 => println!("{_m}StartingMinislot: {}", to_u32(t.val)),
            12 => println!("{_m}PreambleString: {:X}", HexFmt(t.val)),
            13 => println!("{_m}TargetRxPowerAdjust: {}", to_u16(t.val)),
            14 => {
                let _s = match t.val[0] {
                    0 => "(0) - The RPD does not insert Flow Tags.".to_string(),
                    1 => "(1) - The RPD inserts Flow Tags.".to_string(),
                    _ => "Reserved".to_string(),
                };
                println!("{_m}EnableFlowTags: {_s}");
            }
            15 => println!("{_m}ScramblerSeed: {}", to_u32(t.val)),
            //TODO: M*4 16b lsc(1), 16bits Hsc(1), etc.. just printing dec bytes for now.
            16 => println!("{_m}ConfigMultiSectionTimingMer: {:?}", t.val),
            17 => {
                println!("{_m}BwReqAggrControlOfdma:");
                let (_, tlvs) = many1(parse_tlvs)(t.val).unwrap();
                for t in tlvs.iter() {
                    match t.typ {
                        1 => println!("{_m2}MaxReqBlockEnqTimeout: {} microseconds", to_u16(t.val)),
                        2 => println!("{_m2}MaxReqBlockEnqNumber: {}", t.val[0]),
                        _ => println!("{_m2}Unsupported BwReqAggrControlOfdma sub-type"),
                    };
                }
            }
            18 => println!("{_m}UsChanId: {}", t.val[0]),
            19 => println!("{_m}ConfigChangeCount: {}", t.val[0]),
            20 => println!("{_m}DsChanId: {}", t.val[0]),
            21 => println!("{_m}BroadcastImRegionDuration: {}", t.val[0]),
            22 => println!("{_m}UnicastImRegionDuration: {}", t.val[0]),
            23 => {
                println!("{_m}FdxConfig:");

                let (_, tlvs) = many1(parse_tlvs)(t.val).unwrap();
                for t in tlvs.iter() {
                    match t.typ {
                        1 => println!("{_m2}EctSid: {}", to_u16(t.val)),
                        2 => {
                            let _s = match t.val[0] {
                                0 => "(0) - EC for the channel is disabled.".to_string(),
                                1 => "(1) - EC for the channel is enabled.".to_string(),
                                _ => "Reserved".to_string(),
                            };
                            println!("{_m2}EcEnable: {_s}");
                        }
                        _ => println!("{_m2}Unsupported FdxConfig sub-type"),
                    };
                }
            }
            _ => println!("{_m}Unsupported UsOfdmaChannelConfig sub-type"),
        };
    }
}

fn complex_tlv_dsoob55d1(tlv: &RphyTlv, margin: usize) {
    println!("{}DsOob55d1:", " ".repeat(margin));

    let (_, tlvs) = many1(parse_tlvs)(tlv.val).unwrap();
    let _m = " ".repeat(margin + 2);

    for t in tlvs.iter() {
        match t.typ {
            1 => println!("{_m}AdminState: {}", AdminStateType(t.val[0])),
            2 => println!("{_m}CcapCoreOwner: {:X}", HexFmt(t.val)),
            3 => {
                let _s = match t.val[0] {
                    0 => "(0) - Channel is not muted.".to_string(),
                    1 => "(1) - Channel is muted.".to_string(),
                    _ => "Reserved".to_string(),
                };
                println!("{_m}RfMute: {_s}");
            }
            4 => println!("{_m}Frequency: {} Hertz", to_u32(t.val)),
            5 => println!("{_m}PowerAdjust: {} TenthdB", to_u16(t.val)),
            6 => println!("{_m}SecondFrequency: {} Hertz", to_u32(t.val)),
            7 => println!("{_m}SfPowerAdjust: {}", to_u32(t.val)),
            8 => println!("{_m}SfAdminState: {}", AdminStateType(t.val[0])),
            9 => {
                let _s = match t.val[0] {
                    0 => "(0) - Channel is not muted.".to_string(),
                    1 => "(1) - Channel is muted.".to_string(),
                    _ => "Reserved".to_string(),
                };
                println!("{_m}SfRfMute: {_s}");
            }
            _ => println!(
                "{_m}Unsupported DsOob55d1 sub-type: type:{}{:?}",
                t.typ, t.val
            ),
        };
    }
}

fn complex_tlv_usoob55d1(tlv: &RphyTlv, margin: usize) {
    println!("{}UsOob55d1:", " ".repeat(margin));

    let (_, tlvs) = many1(parse_tlvs)(tlv.val).unwrap();
    let _m = " ".repeat(margin + 2);
    for t in tlvs.iter() {
        match t.typ {
            1 => println!("{_m}AdminState: {}", AdminStateType(t.val[0])),
            2 => println!("{_m}CcapCoreOwner: {:X}", HexFmt(t.val)),
            3 => println!("{_m}Frequency: {} Hertz", to_u32(t.val)),
            4 => println!("{_m}VarpdDeviceId: {}", to_u32(t.val)),
            5 => println!("{_m}VarpdRfPortId: {}", t.val[0]),
            6 => println!("{_m}VarpdDemodId: {}", t.val[0]),
            7 => println!("{_m}TargetRxPowerAdjust: {} TenthdB", to_u16(t.val)),
            _ => println!("{_m}Unsupported UsOob55d1 sub-type"),
        };
    }
}

fn complex_tlv_usrfport(tlv: &RphyTlv, margin: usize) {
    /*
    UsRfPort	                    Complex TLV	                        98	    variable
    AdminState	                    AdminStateType	                    98.1	1  AdminStateType()
    BwReqAggrControl	            Complex TLV	                        98.2
        MaxReqBlockEnqTimeout	        UnsignedShort	                    98.2.1	2  microseconds
        MaxReqBlockEnqNumber	        UnsignedByte	                    98.2.2	1
    BaseTargetRxPower	            Short	                            98.3	2
    FdxAllocSpectrumWidth	        UnsignedShort	                    98.4	2  MHz
    */

    println!("{}UsRfPort:", " ".repeat(margin));
    let (_, tlvs) = many1(parse_tlvs)(tlv.val).unwrap();
    let _m = " ".repeat(margin + 2);
    let _m4 = " ".repeat(margin + 4);
    for t in tlvs.iter() {
        match t.typ {
            1 => println!("{_m}AdminState: {}", AdminStateType(t.val[0])),
            2 => {
                println!("{_m}BwReqAggrControl:");
                let (_, tlvs) = many1(parse_tlvs)(t.val).unwrap();
                for t in tlvs.iter() {
                    match t.typ {
                        1 => println!("{_m4}MaxReqBlockEnqTimeout: {} microseconds", to_u16(t.val)),
                        2 => println!("{_m4}MaxReqBlockEnqNumber: {}", t.val[0]),
                        _ => println!("{_m4}Unsupported BwReqAggrControl sub-type"),
                    };
                }
            }
            3 => println!("{_m}BaseTargetRxPower: {} microseconds", to_u16(t.val)),
            4 => println!("{_m}FdxAllocSpectrumWidth: {} MHz", to_u16(t.val)),
            _ => println!("{_m}Unsupported UsRfPort sub-type"),
        };
    }
}

fn complex_tlv_rfmconfig(tlv: &RphyTlv, margin: usize) {
    /*
    RfmConfig	                    Complex TLV	                        160	    variable
    DsPowerGainConfig	            Complex TLV	                        160.1	variable
        DsPowerGainIndex	            UnsignedByte	                    160.1.1	1
        DsCfgRfmGain	                Short	                            160.1.2	2
    UsPowerGainConfig	            Complex TLV	                        160.2	variable
        UsPowerGainIndex	            UnsignedByte	                    160.2.1	1
        UsCfgRfmGain	                Short	                            160.2.2	2
    DsTiltCfg	                    Complex TLV	                        160.3	variable
        DsTiltCtrlIndex	                UnsignedByte	                    160.3.1	1
        DsRfmTilt	                    Short	                            160.3.2	2

    */
    println!("{}RfmConfig:", " ".repeat(margin));
    let (_, tlvs) = many1(parse_tlvs)(tlv.val).unwrap();
    let _m = " ".repeat(margin + 2);
    let _m4 = " ".repeat(margin + 4);
    for t in tlvs.iter() {
        match t.typ {
            1 => {
                println!("{_m}DsPowerGainConfig:");
                let (_, tlvs) = many1(parse_tlvs)(t.val).unwrap();
                for t in tlvs.iter() {
                    match t.typ {
                        1 => println!("{_m4}DsPowerGainIndex: {}", t.val[0]),
                        2 => println!("{_m4}DsCfgRfmGain: {} TenthdB", to_u16(t.val)),
                        _ => println!("{_m4}Unsupported DsPowerGainConfig sub-type"),
                    };
                }
            }
            2 => {
                println!("{_m}UsPowerGainConfig:");
                let (_, tlvs) = many1(parse_tlvs)(t.val).unwrap();
                for t in tlvs.iter() {
                    match t.typ {
                        1 => println!("{_m4}UsPowerGainIndex: {}", t.val[0]),
                        2 => println!("{_m4}UsCfgRfmGain: {} TenthdB", to_u16(t.val)),
                        _ => println!("{_m4}Unsupported UsPowerGainConfig sub-type"),
                    };
                }
            }
            3 => {
                println!("{_m}DsTiltCfg:");
                let (_, tlvs) = many1(parse_tlvs)(t.val).unwrap();
                for t in tlvs.iter() {
                    match t.typ {
                        1 => println!("{_m4}DsTiltCtrlIndex: {}", t.val[0]),
                        2 => println!("{_m4}DsRfmTilt: {} TenthdB", to_u16(t.val)),
                        _ => println!("{_m4}Unsupported DsTiltCfg sub-type"),
                    };
                }
            }
            _ => println!("{_m}Unsupported RfmConfig sub-type"),
        };
    }
}

fn complex_tlv_usscqamprofilequery(tlv: &RphyTlv, margin: usize) {
    /*
    UsScQamProfileQuery	            Complex TLV	                        150
        QueryScQamChannelType	        UpstreamChantype	                150.1	1  UpstreamChannelType()
        QueryScQamWidth	                UnsignedInt	                        150.2	4
        QueryIucCode	                Complex TLV	                        150.3
            QueryScQamCode	                UnsignedByte	                    150.3.1	1
            QueryScQamPreambleLen	        UnsignedShort	                    150.3.2	2
            QueryScQamPreambleModType	    PreambleType	                    150.3.3	1  PreambleType()
            QueryScQamModulationType	    UnsignedByte	                    150.3.4	1
            QueryScQamGuardTime	            UnsignedByte	                    150.3.5	1
    */
    println!("{}UsScQamProfileQuery:", " ".repeat(margin));
    let (_, tlvs) = many1(parse_tlvs)(tlv.val).unwrap();
    let _m = " ".repeat(margin + 2);
    let _m4 = " ".repeat(margin + 4);
    for t in tlvs.iter() {
        match t.typ {
            1 => println!(
                "{_m}QueryScQamChannelType: {}",
                UpstreamChannelType(t.val[0])
            ),
            2 => println!("{_m}QueryScQamWidth: {} Hertz", to_u32(t.val)),
            3 => {
                println!("{_m}QueryIucCode:");
                let (_, tlvs) = many1(parse_tlvs)(t.val).unwrap();
                for t in tlvs.iter() {
                    match t.typ {
                        1 => println!("{_m4}QueryScQamCode: {}", t.val[0]),
                        // B.5.5.17.3.2 QueryScQamPreambleLen states variable but i think this is incorrect. HexFmt for now
                        2 => println!("{_m4}QueryScQamPreambleLen: {:X}", HexFmt(t.val)), //
                        3 => {
                            println!("{_m4}QueryScQamPreambleModType: {}", PreambleType(t.val[0]));
                        }
                        4 => println!(
                            "{_m4}QueryScQamModulationType: {}",
                            QueryScQamModulationType(t.val[0])
                        ),
                        5 => println!("{_m4}QueryScQamGuardTime: {}", t.val[0]),
                        _ => println!("{_m4}Unsupported QueryIucCode sub-type"),
                    };
                }
            }
            _ => println!("{_m}Unsupported UsScQamProfileQuery sub-type"),
        };
    }
}

fn complex_tlv_usscqamprofileresponse(tlv: &RphyTlv, margin: usize) {
    /*
    UsScQamProfileResponse	        Complex TLV	                        151
        ResponseScQamPreambleString	    HexBinary	                        151.1	Variable
        ResponseIucCode	                Complex TLV	                        151.2
            ResponseScQamCode	            UnsignedByte	                    151.2.1	1
            ResponseScQamPreambleLen	    UnsignedShort	                    151.2.2	2
            ResponseScQamPreambleOffset	    UnsignedShort	                    151.2.3	2
            ResponseScQamPreambleModType	PreambleType	                    151.2.4	1 PreambleType()
            ResponseScQamScramblerSeed	    UnsignedShort	                    151.2.5	2
            ResponseScQamGuardTime	        UnsignedByte	                    151.2.6	1
        */
    println!("{}UsScQamProfileResponse:", " ".repeat(margin));
    let (_, tlvs) = many1(parse_tlvs)(tlv.val).unwrap();
    let _m = " ".repeat(margin + 2);
    let _m2 = " ".repeat(margin + 4);
    for t in tlvs.iter() {
        match t.typ {
            1 => {
                println!("{_m}ResponseScQamPreambleString:");
                t.val.iter().for_each(|x| {
                    print!("{x:08b}");
                });
                println!(" ");
            }
            2 => {
                //B.5.5.18.2 Response Interval Usage Code TLVs
                println!("{_m}ResponseIucCode:");
                let (_, tlvs) = many1(parse_tlvs)(t.val).unwrap();
                for t in tlvs.iter() {
                    match t.typ {
                        1 => println!("{_m2}ResponseScQamCode: {}", t.val[0]),
                        2 => println!("{_m2}ResponseScQamPreambleLen: {} bits", to_u16(t.val)),
                        3 => println!("{_m2}ResponseScQamPreambleOffset: {} bits", to_u16(t.val)),
                        4 => println!(
                            "{_m2}ResponseScQamPreambleModType: {}",
                            PreambleType(t.val[0])
                        ),
                        5 => println!("{_m2}ResponseScQamScramblerSeed: {}", to_u16(t.val)),
                        6 => println!("{_m2}ResponseScQamGuardTime: {}", t.val[0]),
                        _ => println!("{_m2}Unsupported ResponseIucCode sub-type"),
                    };
                }
            }
            _ => println!("{_m}Unsupported UsScQamProfileResponse sub-type"),
        };
    }
}

fn complex_tlv_dsofdmchannelperf(tlv: &RphyTlv, margin: usize) {
    //
    println!("{}DsOfdmChannelPerf:", " ".repeat(margin));
    let (_, tlvs) = many1(parse_tlvs)(tlv.val).unwrap();
    let _m = " ".repeat(margin + 2);
    let _m2 = " ".repeat(margin + 4);
    for t in tlvs.iter() {
        match t.typ {
            1 => println!("{_m}outDiscards: {} packets", to_u64(t.val)),
            2 => println!("{_m}outErrors: {} packets", to_u64(t.val)),
            3 => {
                println!("{_m}DsOfdmProfilePerf:");
                let (_, pp) = many1(parse_tlvs)(t.val).unwrap();
                for p in pp.iter() {
                    match p.typ {
                        1 => println!("{_m2}ProfileIndex: {}", p.val[0]),
                        2 => println!("{_m2}outCodewords: {}", to_u64(p.val)),
                        _ => println!("{_m2}Unsupported DsOfdmProfilePerf sub-type"),
                    };
                }
            }
            4 => println!("{_m}outPackets: {} packets", to_u64(t.val)),
            5 => println!("{_m}discontinuityTime:"),
            6 => {
                println!("{_m}DsOfdmPlcPerf:");
                let (_, pl) = many1(parse_tlvs)(t.val).unwrap();
                for l in pl.iter() {
                    match l.typ {
                        1 => println!("{_m2}outDiscards: {} packets", to_u64(l.val)),
                        2 => println!("{_m2}outErrors: {} packets", to_u64(l.val)),
                        3 => println!("{_m2}outPackets: {} packets", to_u64(l.val)),
                        4 => println!("{_m2}discontinuityTime: {}", to_date_rfc2578(l)),
                        _ => println!("{_m2}Unsupported DsOfdmProfilePerf sub-type"),
                    };
                }
            }
            7 => println!("{_m}operStatusDsOfdm: {}", OperationalStatusType(t.val[0])),
            8 => println!("{_m}PlcFrameTimeAlignment: {}", to_u64(t.val)),
            _ => println!("{_m}Unsupported DsOfdmChannelPerf sub-type"),
        }
    }
}

fn complex_tlv_usscqamchannelperf(tlv: &RphyTlv, margin: usize) {
    println!("{}UsScQamChannelPerf:", " ".repeat(margin));
    let (_, tlvs) = many1(parse_tlvs)(tlv.val).unwrap();
    let _m = " ".repeat(margin + 2);
    let _m2 = " ".repeat(margin + 4);
    for t in tlvs.iter() {
        match t.typ {
            1 => {
                println!("{_m}UsScChanLowIucStats:");
                let (_, tlvs) = many1(parse_tlvs)(t.val).unwrap();
                for t in tlvs.iter() {
                    match t.typ {
                        1 => println!("{_m}UsIuc: {}", t.val[0]),
                        2 => println!("{_m}UnicastOpportunities: {}", to_u64(t.val)),
                        3 => println!("{_m}UnicastOpCollisions: {}", to_u64(t.val)),
                        4 => println!("{_m}UnicastOpNoEnergy: {}", to_u64(t.val)),
                        5 => println!("{_m}UnicastOpErrors: {}", to_u64(t.val)),
                        6 => println!("{_m}MulticastOpportunities: {}", to_u64(t.val)),
                        7 => println!("{_m}McastOpCollisions: {}", to_u64(t.val)),
                        8 => println!("{_m}McastOpNoEnergy: {}", to_u64(t.val)),
                        9 => println!("{_m}McastOpErrors: {}", to_u64(t.val)),
                        10 => println!("{_m}GoodFecCw: {}", to_u64(t.val)),
                        11 => println!("{_m}CorrectedFecCw: {}", to_u64(t.val)),
                        12 => println!("{_m}UncorrectFecCw: {}", to_u64(t.val)),
                        _ => println!("{_m}Unsupported UsScChanLowIucStats sub-type"),
                    };
                }
            }
            2 => {
                println!("{_m}UsScChanHiIucStats:");
                let (_, tlvs) = many1(parse_tlvs)(t.val).unwrap();
                for t in tlvs.iter() {
                    match t.typ {
                        1 => println!("{_m}UsIuc: {}", t.val[0]),
                        2 => println!("{_m}ScheduledGrants: {}", to_u64(t.val)),
                        3 => println!("{_m}NoEnergyBursts: {}", to_u64(t.val)),
                        4 => println!("{_m}NoPreambleBursts: {}", to_u64(t.val)),
                        5 => println!("{_m}ErrorBursts: {}", to_u64(t.val)),
                        6 => println!("{_m}GoodFecCw: {}", to_u64(t.val)),
                        7 => println!("{_m}CorrectedFecCw: {}", to_u64(t.val)),
                        8 => println!("{_m}UncorrectFecCw: {}", to_u64(t.val)),
                        _ => println!("{_m}Unsupported UsScChanHiIucStats sub-type"),
                    };
                }
            }
            3 => println!("{_m}HcsErrors: {}", to_u64(t.val)),
            4 => println!("{_m}LateMaps: {}", to_u64(t.val)),
            5 => println!("{_m}IllegalMaps: {}", to_u64(t.val)),
            6 => println!("{_m}DiscardedRequests: {}", to_u64(t.val)),
            7 => println!("{_m}ChannelSnr: {} TenthdB", to_u16(t.val)),
            8 => println!("{_m}discontinuityTime: {}", to_date_rfc2578(t)),
            9 => println!("{_m}operStatusUsScQam: {}", OperationalStatusType(t.val[0])),
            10 => {
                println!("{_m}UcdRefreshStatusScqam:");
                let (_, tlvs) = many1(parse_tlvs)(t.val).unwrap();
                for t in tlvs.iter() {
                    match t.typ {
                        1 => {
                            let _s = match t.val[0] {
                                0 => "(0) - The RPD is not requesting to perform the UCD change procedure for the channel.".to_string(),
                                1 => "(1) - The RPD is requesting to perform the UCD change procedure for the channel.".to_string(),
                                _ => "Reserved".to_string(),
                            };
                            println!("{_m}UcdRefreshRequestScqam: {_s}");
                        }
                        2 => println!(
                            "{_m}UcdRefreshReasonScqam: {}",
                            str::from_utf8(t.val).unwrap().trim_end_matches('\0')
                        ),
                        _ => println!("{_m}Unsupported UcdRefreshStatusScqam sub-type"),
                    };
                }
            }
            _ => println!("{_m}Unsupported UsScQamChannelPerf sub-type"),
        };
    }
}

fn complex_tlv_usofdmachannelperf(tlv: &RphyTlv, margin: usize) {
    println!("{}UsOfdmaChannelPerf:", " ".repeat(margin));
    let (_, tlvs) = many1(parse_tlvs)(tlv.val).unwrap();
    let _m = " ".repeat(margin + 2);
    let _m2 = " ".repeat(margin + 4);
    for t in tlvs.iter() {
        match t.typ {
            1 => {
                println!("{_m}UsOfdmaChanLowIucStats:");
                let (_, tlvs) = many1(parse_tlvs)(t.val).unwrap();
                for t in tlvs.iter() {
                    match t.typ {
                        1 => println!("{_m2}UsIuc: {}", t.val[0]),
                        2 => println!("{_m2}UnicastOpportunities: {}", to_u64(t.val)),
                        3 => println!("{_m2}UnicastOpCollisions: {}", to_u64(t.val)),
                        4 => println!("{_m2}UnicastOpNoEnergy: {}", to_u64(t.val)),
                        5 => println!("{_m2}UnicastOpErrors: {}", to_u64(t.val)),
                        6 => println!("{_m2}MulticastOpportunities: {}", to_u64(t.val)),
                        7 => println!("{_m2}McastOpCollisions: {}", to_u64(t.val)),
                        8 => println!("{_m2}McastOpNoEnergy: {}", to_u64(t.val)),
                        9 => println!("{_m2}McastOpErrors: {}", to_u64(t.val)),
                        10 => println!("{_m2}NumPredecodePass: {}", to_u64(t.val)),
                        11 => println!("{_m2}NumPostdecodePass: {}", to_u64(t.val)),
                        12 => println!("{_m2}NumPostdecodeFail: {}", to_u64(t.val)),
                        _ => println!("{_m}Unsupported UsOfdmaChanLowIucStats sub-type"),
                    };
                }
            }
            2 => {
                println!("{_m}UsOfdmaChanHiIucStats:");
                let (_, tlvs) = many1(parse_tlvs)(t.val).unwrap();
                for t in tlvs.iter() {
                    match t.typ {
                        1 => println!("{_m2}UsIuc: {}", t.val[0]),
                        2 => println!("{_m2}ScheduledGrants: {}", to_u64(t.val)),
                        3 => println!("{_m2}NoEnergyBursts: {}", to_u64(t.val)),
                        4 => println!("{_m2}NoPreambleBursts: {}", to_u64(t.val)),
                        5 => println!("{_m2}ErrorBursts: {}", to_u64(t.val)),
                        6 => println!("{_m2}NumPredecodePass: {}", to_u64(t.val)),
                        7 => println!("{_m2}NumPostdecodePass: {}", to_u64(t.val)),
                        8 => println!("{_m2}NumPostdecodeFail: {}", to_u64(t.val)),
                        9 => println!("{_m2}AverageMer: {}", to_u16(t.val)),
                        _ => println!("{_m2}Unsupported UsOfdmaChanHiIucStats sub-type"),
                    };
                }
            }
            3 => println!("{_m}HcsErrors: {}", to_u64(t.val)),
            4 => println!("{_m}LateMaps: {}", to_u64(t.val)),
            5 => println!("{_m}IllegalMaps: {}", to_u64(t.val)),
            6 => println!("{_m}DiscardedRequests: {}", to_u64(t.val)),
            7 => println!("{_m}ProbeGrants: {}", to_u64(t.val)),
            8 => println!("{_m}discontinuityTime: {}", to_date_rfc2578(t)),
            9 => println!("{_m}operStatusUsOfdma: {}", t.val[0]),
            10 => {
                println!("{_m}UcdRefreshStatusOfdma:");
                let (_, tlvs) = many1(parse_tlvs)(t.val).unwrap();
                for t in tlvs.iter() {
                    match t.typ {
                        1 => {
                            let _s = match t.val[0] {
                                0 => "(0) - The RPD is not requesting to perform the UCD change procedure for the channel.".to_string(),
                                1 => "(1) - The RPD is requesting to perform the UCD change procedure for the channel.".to_string(),
                                _ => "Reserved".to_string(),
                            };
                            println!("{_m2}UcdRefreshRequestOfdma: {_s}");
                        }
                        2 => println!(
                            "{_m2}UcdRefreshReasonOfdma: {}",
                            str::from_utf8(t.val).unwrap().trim_end_matches('\0')
                        ),
                        _ => println!("{_m2}Unsupported UcdRefreshStatusOfdma sub-type"),
                    };
                }
            }
            _ => println!("{_m}Unsupported UsOfdmaChannelPerf sub-type"),
        };
    }
}
