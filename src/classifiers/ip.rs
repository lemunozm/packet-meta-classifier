pub mod analyzer {
    use crate::analyzer::{Analyzer, AnalyzerStatus};
    use crate::classifiers::ClassifierId;
    use crate::flow::{FlowDef, GenericFlow};

    use std::convert::{TryFrom, TryInto};
    use std::net::{Ipv4Addr, Ipv6Addr};

    pub enum Protocol {
        Tcp,
        Udp,
    }

    impl TryFrom<u8> for Protocol {
        type Error = ();
        fn try_from(value: u8) -> Result<Protocol, ()> {
            match value {
                6 => Ok(Self::Tcp),
                17 => Ok(Self::Udp),
                _ => Err(()),
            }
        }
    }

    impl Protocol {
        fn classifier_id(&self) -> ClassifierId {
            match self {
                Self::Tcp => ClassifierId::Tcp,
                Self::Udp => ClassifierId::Udp,
            }
        }
    }

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
        pub protocol: Protocol,
        pub version: Version,
    }

    impl Default for IpAnalyzer {
        fn default() -> Self {
            Self {
                protocol: Protocol::Udp,
                version: Version::V4(V4 {
                    source: Ipv4Addr::new(0, 0, 0, 0),
                    dest: Ipv4Addr::new(0, 0, 0, 0),
                }),
            }
        }
    }

    impl Analyzer for IpAnalyzer {
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

            let header_length = ((data[0] & 0x0F) as usize) << 2;
            match data[9].try_into() {
                Ok(protocol) => self.protocol = protocol,
                Err(_) => return AnalyzerStatus::Abort,
            }
            AnalyzerStatus::Next(self.protocol.classifier_id(), &data[header_length..])
        }

        fn classifier_id() -> ClassifierId {
            ClassifierId::Ip
        }

        fn next_classifiers() -> Vec<ClassifierId> {
            vec![ClassifierId::Tcp, ClassifierId::Udp]
        }

        fn identify_flow(&self) -> Option<FlowDef> {
            None
        }

        fn create_flow(&self) -> Box<dyn GenericFlow> {
            unreachable!()
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }

        fn reset(&mut self) {
            *self = Self::default();
        }
    }
}

pub mod rules {
    use super::analyzer::{IpAnalyzer, Version};
    use crate::flow::NoFlow;
    use crate::rule::RuleValue;

    use std::net::IpAddr;

    #[derive(Debug)]
    pub struct Ip;

    impl RuleValue for Ip {
        type Flow = NoFlow;
        type Analyzer = IpAnalyzer;

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

    impl RuleValue for IpVersion {
        type Flow = NoFlow;
        type Analyzer = IpAnalyzer;

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

    impl RuleValue for IpSource {
        type Flow = NoFlow;
        type Analyzer = IpAnalyzer;

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

    impl RuleValue for IpDest {
        type Flow = NoFlow;
        type Analyzer = IpAnalyzer;

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
