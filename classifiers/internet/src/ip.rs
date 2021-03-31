pub mod analyzer {
    use crate::ClassifierId;

    use gpc_core::base::analyzer::{Analyzer, AnalyzerResult};
    use gpc_core::base::flow::NoFlow;
    use gpc_core::packet::{Direction, Packet};

    use std::io::Write;
    use std::net::{Ipv4Addr, Ipv6Addr};

    pub struct V4 {
        pub source: Ipv4Addr,
        pub dest: Ipv4Addr,
    }

    pub struct V6 {
        pub source: Ipv6Addr,
        pub dest: Ipv6Addr,
    }

    pub enum Version {
        V4(V4),
        V6(V6),
    }

    pub struct IpAnalyzer {
        pub protocol: u8,
        pub version: Version,
    }

    impl Default for IpAnalyzer {
        fn default() -> Self {
            Self {
                protocol: 0,
                version: Version::V4(V4 {
                    source: Ipv4Addr::new(0, 0, 0, 0),
                    dest: Ipv4Addr::new(0, 0, 0, 0),
                }),
            }
        }
    }

    impl Analyzer<ClassifierId> for IpAnalyzer {
        const ID: ClassifierId = ClassifierId::Ip;
        const PREV_ID: ClassifierId = ClassifierId::None;
        type Flow = NoFlow<Self>;

        fn analyze(packet: &Packet) -> AnalyzerResult<Self, ClassifierId> {
            let ip_version = (packet.data[0] & 0xF0) >> 4;

            let (analyzer, header_len) = match ip_version {
                4 => (
                    Self {
                        protocol: packet.data[9],
                        version: Version::V4(V4 {
                            source: Ipv4Addr::from(*array_ref![packet.data, 12, 4]),
                            dest: Ipv4Addr::from(*array_ref![packet.data, 16, 4]),
                        }),
                    },
                    ((packet.data[0] & 0x0F) as usize) << 2,
                ),
                6 => (
                    Self {
                        protocol: packet.data[6],
                        version: Version::V6(V6 {
                            source: Ipv6Addr::from(*array_ref![packet.data, 8, 16]),
                            dest: Ipv6Addr::from(*array_ref![packet.data, 24, 16]),
                        }),
                    },
                    40,
                ),
                _ => return AnalyzerResult::Abort,
            };

            let next_classifier = match analyzer.protocol {
                6 => ClassifierId::Tcp,
                //17 => ClassifierId::Udp, //TODO: uncomment when exists UDP analyzer.
                _ => ClassifierId::None,
            };

            AnalyzerResult::Next(analyzer, next_classifier, header_len)
        }

        fn write_flow_signature(&self, mut signature: impl Write, direction: Direction) -> bool {
            match &self.version {
                Version::V4(v4) => {
                    let (first, second) = match direction {
                        Direction::Uplink => (v4.source.octets(), v4.dest.octets()),
                        Direction::Downlink => (v4.dest.octets(), v4.source.octets()),
                    };
                    signature.write_all(&first).unwrap();
                    signature.write_all(&second).unwrap();
                }
                Version::V6(v6) => {
                    let (first, second) = match direction {
                        Direction::Uplink => (v6.source.octets(), v6.dest.octets()),
                        Direction::Downlink => (v6.dest.octets(), v6.source.octets()),
                    };
                    signature.write_all(&first).unwrap();
                    signature.write_all(&second).unwrap();
                }
            };

            // For IP, we only add the to signature but we do not want to create an IP flow
            false
        }
    }
}

pub mod expression {
    use super::analyzer::{IpAnalyzer, Version};

    use crate::ClassifierId;
    use gpc_core::base::expression_value::ExpressionValue;
    use gpc_core::base::flow::NoFlow;

    use std::net::IpAddr;

    #[derive(Debug)]
    pub struct Ip;

    impl ExpressionValue<ClassifierId> for Ip {
        type Analyzer = IpAnalyzer;

        fn description() -> &'static str {
            "Valid if the packet is TCP"
        }

        fn check(&self, _analyzer: &IpAnalyzer, _: &NoFlow<IpAnalyzer>) -> bool {
            true
        }
    }

    #[derive(Debug)]
    pub enum IpVersion {
        V4,
        V6,
    }

    impl ExpressionValue<ClassifierId> for IpVersion {
        type Analyzer = IpAnalyzer;

        fn description() -> &'static str {
            "Valid if the IP version of the packet matches the given version"
        }

        fn check(&self, analyzer: &IpAnalyzer, _: &NoFlow<IpAnalyzer>) -> bool {
            match self {
                Self::V4 => matches!(analyzer.version, Version::V4(_)),
                Self::V6 => matches!(analyzer.version, Version::V6(_)),
            }
        }
    }

    #[derive(Debug)]
    pub struct IpSource(pub IpAddr);

    impl ExpressionValue<ClassifierId> for IpSource {
        type Analyzer = IpAnalyzer;

        fn description() -> &'static str {
            "Valid if the source IP address of the packet matches the given address"
        }

        fn check(&self, analyzer: &IpAnalyzer, _: &NoFlow<IpAnalyzer>) -> bool {
            match &analyzer.version {
                Version::V4(ipv4) => ipv4.source == self.0,
                Version::V6(ipv6) => ipv6.source == self.0,
            }
        }
    }

    #[derive(Debug)]
    pub struct IpDest(pub IpAddr);

    impl ExpressionValue<ClassifierId> for IpDest {
        type Analyzer = IpAnalyzer;

        fn description() -> &'static str {
            "Valid if the destination IP address of the packet matches the given address"
        }

        fn check(&self, analyzer: &IpAnalyzer, _: &NoFlow<IpAnalyzer>) -> bool {
            match &analyzer.version {
                Version::V4(ipv4) => ipv4.dest == self.0,
                Version::V6(ipv6) => ipv6.dest == self.0,
            }
        }
    }
}
