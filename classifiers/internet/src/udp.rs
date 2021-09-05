use crate::ClassifierId;

use gpc_core::base::builder::Builder;

pub struct UdpBuilder;
impl<'a> Builder<'a, ClassifierId> for UdpBuilder {
    type Analyzer = analyzer::UdpAnalyzer<'a>;
}

mod analyzer {
    use super::flow::UdpFlow;

    use crate::ClassifierId;

    use gpc_core::base::analyzer::{Analyzer, AnalyzerInfo, AnalyzerResult};
    use gpc_core::packet::{Direction, Packet};

    use std::io::Write;

    pub struct UdpAnalyzer<'a> {
        pub header: &'a [u8],
        pub payload_len: u16,
    }

    impl<'a> UdpAnalyzer<'a> {
        pub fn source_port(&self) -> u16 {
            u16::from_be_bytes(*array_ref![self.header, 0, 2])
        }

        pub fn dest_port(&self) -> u16 {
            u16::from_be_bytes(*array_ref![self.header, 2, 2])
        }

        fn expected_l7_classifier(server_port: u16) -> ClassifierId {
            match server_port {
                _ => ClassifierId::None,
            }
        }
    }

    impl<'a> Analyzer<'a, ClassifierId> for UdpAnalyzer<'a> {
        const ID: ClassifierId = ClassifierId::Udp;
        const PREV_ID: ClassifierId = ClassifierId::Ip;

        type Flow = UdpFlow;

        fn build(&Packet { data, direction }: &'a Packet) -> AnalyzerResult<Self, ClassifierId> {
            let header_len = 8;
            let payload_len = u16::from_be_bytes(*array_ref![data, 4, 2]);

            let analyzer = Self {
                header: &data[0..header_len],
                payload_len,
            };

            let next_protocol = match analyzer.payload_len > 0 {
                true => {
                    let server_port = match direction {
                        Direction::Uplink => analyzer.dest_port(),
                        Direction::Downlink => analyzer.source_port(),
                    };
                    Self::expected_l7_classifier(server_port)
                }
                false => ClassifierId::None,
            };

            Ok(AnalyzerInfo {
                analyzer,
                next_classifier_id: next_protocol,
                bytes_parsed: header_len,
            })
        }

        fn write_flow_signature(&self, mut signature: impl Write, direction: Direction) -> bool {
            let (source, dest) = (&self.header[0..2], &self.header[2..4]);
            let (first, second) = match direction {
                Direction::Uplink => (source, dest),
                Direction::Downlink => (dest, source),
            };

            signature.write_all(first).unwrap();
            signature.write_all(second).unwrap();
            true
        }

        fn create_flow(&self, _direction: Direction) -> UdpFlow {
            UdpFlow {}
        }

        fn update_flow(&self, _flow: &mut UdpFlow, _direction: Direction) {}
    }
}

mod flow {
    pub struct UdpFlow {}
}

pub mod expression {
    use super::analyzer::UdpAnalyzer;
    use super::flow::UdpFlow;

    use crate::ClassifierId;

    use gpc_core::base::expression_value::ExpressionValue;

    #[derive(Debug)]
    pub struct UdpSourcePort(pub u16);

    impl ExpressionValue<ClassifierId> for UdpSourcePort {
        type Builder = super::UdpBuilder;

        fn description() -> &'static str {
            "Valid if the source UDP port of the packet matches the given port"
        }

        fn check(&self, analyzer: &UdpAnalyzer, _flow: &UdpFlow) -> bool {
            self.0 == analyzer.source_port()
        }
    }

    #[derive(Debug)]
    pub struct UdpDestPort(pub u16);

    impl ExpressionValue<ClassifierId> for UdpDestPort {
        type Builder = super::UdpBuilder;

        fn description() -> &'static str {
            "Valid if the destination UDP port of the packet matches the given port"
        }

        fn check(&self, analyzer: &UdpAnalyzer, _flow: &UdpFlow) -> bool {
            self.0 == analyzer.dest_port()
        }
    }
}
