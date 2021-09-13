use crate::Config;

use pmc_core::base::classifier::Classifier;

pub struct IpClassifier;
impl<'a> Classifier<'a, Config> for IpClassifier {
    type Analyzer = analyzer::IpAnalyzer<'a>;
}

mod analyzer {
    use crate::{ClassifierId, Config, FlowSignature};

    use pmc_core::base::analyzer::{Analyzer, AnalyzerInfo, AnalyzerResult, BuildFlow};
    use pmc_core::packet::{Direction, Packet};

    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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

    impl<'a> Analyzer<'a, Config> for IpAnalyzer<'a> {
        const ID: ClassifierId = ClassifierId::Ip;
        const PREV_ID: ClassifierId = ClassifierId::None;

        type Flow = ();

        fn update_flow_id(
            signature: &mut FlowSignature,
            &Packet { data, direction }: &Packet,
        ) -> BuildFlow {
            let ip_version = (data[0] & 0xF0) >> 4;
            let (source, dest) = match ip_version {
                4 => (
                    Ipv4Addr::from(*array_ref![data, 12, 4]).to_ipv6_mapped(),
                    Ipv4Addr::from(*array_ref![data, 16, 4]).to_ipv6_mapped(),
                ),
                6 => (
                    Ipv6Addr::from(*array_ref![data, 8, 16]),
                    Ipv6Addr::from(*array_ref![data, 24, 16]),
                ),
                _ => return BuildFlow::Abort("Ip version not valid"),
            };

            let (first, second) = match direction {
                Direction::Uplink => (source, dest),
                Direction::Downlink => (dest, source),
            };

            signature.source_ip = first;
            signature.dest_ip = second;

            BuildFlow::No
        }

        fn build(
            _config: &Config,
            &Packet { data, .. }: &'a Packet,
            _: &(),
        ) -> AnalyzerResult<Self, ClassifierId> {
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
    }
}

pub mod expression {
    use super::analyzer::{IpAnalyzer, Version};
    use super::IpClassifier;

    use crate::Config;

    use pmc_core::base::expression_value::ExpressionValue;

    use std::net::IpAddr;

    #[derive(Debug)]
    pub struct Ip;
    impl ExpressionValue<Config> for Ip {
        type Classifier = IpClassifier;

        fn check(&self, _packet: &IpAnalyzer, _: &()) -> bool {
            true
        }
    }

    pub use super::analyzer::Version as IpVersion;
    impl ExpressionValue<Config> for IpVersion {
        type Classifier = IpClassifier;

        fn check(&self, packet: &IpAnalyzer, _: &()) -> bool {
            match self {
                Self::V4 => matches!(packet.version, Version::V4),
                Self::V6 => matches!(packet.version, Version::V6),
            }
        }
    }

    #[derive(Debug)]
    pub struct IpSource(pub IpAddr);
    impl ExpressionValue<Config> for IpSource {
        type Classifier = IpClassifier;

        fn check(&self, packet: &IpAnalyzer, _: &()) -> bool {
            self.0 == packet.source()
        }
    }

    #[derive(Debug)]
    pub struct IpDest(pub IpAddr);
    impl ExpressionValue<Config> for IpDest {
        type Classifier = IpClassifier;

        fn check(&self, packet: &IpAnalyzer, _: &()) -> bool {
            self.0 == packet.dest()
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq)]
    pub enum IpProto {
        Tcp = 6,
        Udp = 17,
    }
    impl ExpressionValue<Config> for IpProto {
        type Classifier = IpClassifier;

        fn check(&self, packet: &IpAnalyzer, _: &()) -> bool {
            *self as u8 == packet.protocol_code()
        }
    }
}
