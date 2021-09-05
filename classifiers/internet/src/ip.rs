use crate::ClassifierId;

use gpc_core::base::builder::Builder;

pub struct IpBuilder;
impl<'a> Builder<'a, ClassifierId> for IpBuilder {
    type Analyzer = analyzer::IpAnalyzer<'a>;
}

mod analyzer {
    use crate::ClassifierId;

    use gpc_core::base::analyzer::{Analyzer, AnalyzerInfo, AnalyzerResult};
    use gpc_core::packet::{Direction, Packet};

    use std::io::Write;
    use std::net::IpAddr;

    #[derive(Debug, Clone, Copy)]
    pub enum Version {
        V4,
        V6,
    }

    pub struct IpAnalyzer<'a> {
        pub version: Version,
        pub header: &'a [u8],
    }

    impl<'a> IpAnalyzer<'a> {
        pub fn source(&self) -> IpAddr {
            match self.version {
                Version::V4 => IpAddr::from(*array_ref![self.header, 12, 4]),
                Version::V6 => IpAddr::from(*array_ref![self.header, 8, 16]),
            }
        }

        pub fn dest(&self) -> IpAddr {
            match self.version {
                Version::V4 => IpAddr::from(*array_ref![self.header, 16, 4]),
                Version::V6 => IpAddr::from(*array_ref![self.header, 24, 16]),
            }
        }

        pub fn protocol_code(&self) -> u8 {
            match self.version {
                Version::V4 => self.header[9],
                Version::V6 => self.header[6],
            }
        }
    }

    impl<'a> Analyzer<'a, ClassifierId> for IpAnalyzer<'a> {
        const ID: ClassifierId = ClassifierId::Ip;
        const PREV_ID: ClassifierId = ClassifierId::None;

        type Flow = ();

        fn build(&Packet { data, .. }: &'a Packet) -> AnalyzerResult<Self, ClassifierId> {
            let ip_version = (data[0] & 0xF0) >> 4;

            let (version, protocol, header_len) = match ip_version {
                4 => (Version::V4, data[9], ((data[0] & 0x0F) as usize) << 2),
                6 => (Version::V6, data[6], 40),
                _ => return Err("Ip version not valid"),
            };

            let next_classifier_id = match protocol {
                6 => ClassifierId::Tcp,
                17 => ClassifierId::Udp,
                _ => ClassifierId::None,
            };

            Ok(AnalyzerInfo {
                analyzer: Self {
                    version,
                    header: &data[0..header_len],
                },
                next_classifier_id,
                bytes_parsed: header_len,
            })
        }

        fn write_flow_signature(&self, mut signature: impl Write, direction: Direction) -> bool {
            let (source, dest) = match &self.version {
                Version::V4 => (&self.header[12..16], &self.header[16..20]),
                Version::V6 => (&self.header[8..24], &self.header[24..40]),
            };

            let (first, second) = match direction {
                Direction::Uplink => (source, dest),
                Direction::Downlink => (dest, source),
            };
            signature.write_all(&first).unwrap();
            signature.write_all(&second).unwrap();

            // For IP, we only add the to signature but we do not want to create an IP flow
            false
        }
    }
}

pub mod expression {
    use super::analyzer::{IpAnalyzer, Version};
    use super::IpBuilder;

    use crate::ClassifierId;

    use gpc_core::base::expression_value::ExpressionValue;

    use std::net::IpAddr;

    #[derive(Debug)]
    pub struct Ip;

    impl ExpressionValue<ClassifierId> for Ip {
        type Builder = IpBuilder;

        fn description() -> &'static str {
            "Valid if the packet is TCP"
        }

        fn check(&self, _analyzer: &IpAnalyzer, _: &()) -> bool {
            true
        }
    }

    pub use super::analyzer::Version as IpVersion;

    impl ExpressionValue<ClassifierId> for IpVersion {
        type Builder = IpBuilder;

        fn description() -> &'static str {
            "Valid if the IP version of the packet matches the given version"
        }

        fn check(&self, analyzer: &IpAnalyzer, _: &()) -> bool {
            match self {
                Self::V4 => matches!(analyzer.version, Version::V4),
                Self::V6 => matches!(analyzer.version, Version::V6),
            }
        }
    }

    #[derive(Debug)]
    pub struct IpSource(pub IpAddr);

    impl ExpressionValue<ClassifierId> for IpSource {
        type Builder = IpBuilder;

        fn description() -> &'static str {
            "Valid if the source IP address of the packet matches the given address"
        }

        fn check(&self, analyzer: &IpAnalyzer, _: &()) -> bool {
            self.0 == analyzer.source()
        }
    }

    #[derive(Debug)]
    pub struct IpDest(pub IpAddr);

    impl ExpressionValue<ClassifierId> for IpDest {
        type Builder = IpBuilder;

        fn description() -> &'static str {
            "Valid if the destination IP address of the packet matches the given address"
        }

        fn check(&self, analyzer: &IpAnalyzer, _: &()) -> bool {
            self.0 == analyzer.dest()
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq)]
    pub enum IpProto {
        Tcp = 6,
        Udp = 17,
    }

    impl ExpressionValue<ClassifierId> for IpProto {
        type Builder = IpBuilder;

        fn description() -> &'static str {
            "Valid if the IP protocol of the packet matches the given protocol"
        }

        fn check(&self, analyzer: &IpAnalyzer, _: &()) -> bool {
            *self as u8 == analyzer.protocol_code()
        }
    }
}
