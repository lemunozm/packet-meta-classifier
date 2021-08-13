pub mod analyzer {
    use crate::analyzer::{Analyzer, AnalyzerStatus, NoAnalyzer};
    use crate::classifiers::ClassifierId;
    use crate::flow::NoFlow;

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

    impl Analyzer for IpAnalyzer {
        type PrevAnalyzer = NoAnalyzer;
        type Flow = NoFlow<IpAnalyzer>;
        const ID: ClassifierId = ClassifierId::Ip;

        fn analyze<'a>(&mut self, data: &'a [u8]) -> AnalyzerStatus<'a> {
            let ip_version = (data[0] & 0xF0) >> 4;

            let header_len = match ip_version {
                4 => {
                    self.protocol = data[9];
                    self.version = Version::V4(V4 {
                        source: Ipv4Addr::from(*array_ref![data, 12, 4]),
                        dest: Ipv4Addr::from(*array_ref![data, 16, 4]),
                    });
                    ((data[0] & 0x0F) as usize) << 2
                }
                6 => {
                    self.protocol = data[6];
                    self.version = Version::V6(V6 {
                        source: Ipv6Addr::from(*array_ref![data, 8, 16]),
                        dest: Ipv6Addr::from(*array_ref![data, 24, 16]),
                    });
                    40
                }
                _ => return AnalyzerStatus::Abort,
            };

            let next_classifier = match self.protocol {
                6 => ClassifierId::Tcp,
                //17 => ClassifierId::Udp, //TODO: uncomment when exists UDP analyzer.
                _ => return AnalyzerStatus::Finished(&data[header_len..]),
            };

            AnalyzerStatus::Next(next_classifier, &data[header_len..])
        }

        fn write_flow_signature(&self, mut signature: impl Write) -> bool {
            match &self.version {
                Version::V4(v4) => {
                    signature.write(&v4.source.octets()).unwrap();
                    signature.write(&v4.dest.octets()).unwrap();
                }
                Version::V6(v6) => {
                    signature.write(&v6.source.octets()).unwrap();
                    signature.write(&v6.dest.octets()).unwrap();
                }
            };

            // For IP, we only add the signature but we do not want a IP flow itself
            false
        }
    }
}

pub mod expression {
    use super::analyzer::{IpAnalyzer, Version};
    use crate::expression::ExpressionValue;
    use crate::flow::NoFlow;

    use std::net::IpAddr;

    #[derive(Debug)]
    pub struct Ip;

    impl ExpressionValue for Ip {
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

    impl ExpressionValue for IpVersion {
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

    impl ExpressionValue for IpSource {
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

    impl ExpressionValue for IpDest {
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
