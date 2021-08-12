pub mod analyzer {
    use crate::analyzer::{Analyzer, AnalyzerStatus, NoAnalyzer};
    use crate::classifiers::ClassifierId;
    use crate::flow::NoFlow;

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
            self.version = match ip_version {
                4 => Version::V4(V4 {
                    source: Ipv4Addr::from(*array_ref![data, 12, 4]),
                    dest: Ipv4Addr::from(*array_ref![data, 16, 4]),
                }),
                6 => todo!(),
                _ => return AnalyzerStatus::Abort,
            };

            self.protocol = data[9];
            let next_classifier = match self.protocol {
                17 => return AnalyzerStatus::Abort, //TODO: remove when exists UDP analyzer.
                6 => ClassifierId::Tcp,
                _ => return AnalyzerStatus::Abort,
            };

            let header_length = ((data[0] & 0x0F) as usize) << 2;
            AnalyzerStatus::Next(next_classifier, &data[header_length..])
        }
    }
}

pub mod rules {
    use super::analyzer::{IpAnalyzer, Version};
    use crate::expression::ExprValue;
    use crate::flow::NoFlow;

    use std::net::IpAddr;

    #[derive(Debug)]
    pub struct Ip;

    impl ExprValue for Ip {
        type Analyzer = IpAnalyzer;
        type Flow = NoFlow<IpAnalyzer>;

        fn description() -> &'static str {
            "Valid if the packet is TCP"
        }

        fn check(&self, _analyzer: &Self::Analyzer, _flow: &Self::Flow) -> bool {
            true
        }
    }

    #[derive(Debug)]
    pub enum IpVersion {
        V4,
        V6,
    }

    impl ExprValue for IpVersion {
        type Analyzer = IpAnalyzer;
        type Flow = NoFlow<IpAnalyzer>;

        fn description() -> &'static str {
            "Valid if the IP version of the packet matches the given version"
        }

        fn check(&self, analyzer: &Self::Analyzer, _flow: &Self::Flow) -> bool {
            match self {
                Self::V4 => matches!(analyzer.version, Version::V4(_)),
                Self::V6 => matches!(analyzer.version, Version::V6(_)),
            }
        }
    }

    #[derive(Debug)]
    pub struct IpSource(pub IpAddr);

    impl ExprValue for IpSource {
        type Analyzer = IpAnalyzer;
        type Flow = NoFlow<IpAnalyzer>;

        fn description() -> &'static str {
            "Valid if the source IP address of the packet matches the given address"
        }

        fn check(&self, analyzer: &Self::Analyzer, _flow: &Self::Flow) -> bool {
            match &analyzer.version {
                Version::V4(ipv4) => ipv4.source == self.0,
                Version::V6(ipv6) => ipv6.source == self.0,
            }
        }
    }

    #[derive(Debug)]
    pub struct IpDest(pub IpAddr);

    impl ExprValue for IpDest {
        type Analyzer = IpAnalyzer;
        type Flow = NoFlow<IpAnalyzer>;

        fn description() -> &'static str {
            "Valid if the destination IP address of the packet matches the given address"
        }

        fn check(&self, analyzer: &Self::Analyzer, _flow: &Self::Flow) -> bool {
            match &analyzer.version {
                Version::V4(ipv4) => ipv4.dest == self.0,
                Version::V6(ipv6) => ipv6.dest == self.0,
            }
        }
    }
}
