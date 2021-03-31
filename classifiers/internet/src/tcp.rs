use crate::ClassifierId;

use gpc_core::base::builder::Builder;

pub struct TcpBuilder;
impl Builder<ClassifierId> for TcpBuilder {
    type Analyzer = analyzer::TcpAnalyzer;
    type Flow = flow::TcpFlow;
}

mod analyzer {
    use crate::ClassifierId;

    use gpc_core::base::analyzer::{Analyzer, AnalyzerInfo, AnalyzerResult};
    use gpc_core::packet::{Direction, Packet};

    use std::io::Write;

    #[derive(Default)]
    pub struct TcpAnalyzer {
        pub source_port: u16,
        pub dest_port: u16,
    }

    impl Analyzer<ClassifierId> for TcpAnalyzer {
        const ID: ClassifierId = ClassifierId::Tcp;
        const PREV_ID: ClassifierId = ClassifierId::Ip;

        fn build(packet: &Packet) -> AnalyzerResult<Self, ClassifierId> {
            let analyzer = Self {
                source_port: u16::from_be_bytes(*array_ref![packet.data, 0, 2]),
                dest_port: u16::from_be_bytes(*array_ref![packet.data, 2, 2]),
            };

            let header_len = (((packet.data[12] & 0xF0) as usize) >> 4) << 2;

            let next_protocol = match packet.data.len() - header_len > 0 {
                true => {
                    let server_port = match packet.direction {
                        Direction::Uplink => analyzer.dest_port,
                        Direction::Downlink => analyzer.source_port,
                    };
                    Self::expected_l7_protocol(server_port)
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
            let (first, second) = match direction {
                Direction::Uplink => (self.source_port, self.dest_port),
                Direction::Downlink => (self.dest_port, self.source_port),
            };

            signature.write_all(&first.to_le_bytes()).unwrap();
            signature.write_all(&second.to_le_bytes()).unwrap();
            true
        }
    }

    impl TcpAnalyzer {
        fn expected_l7_protocol(server_port: u16) -> ClassifierId {
            match server_port {
                80 => ClassifierId::Http,
                8080 => ClassifierId::Http,
                _ => ClassifierId::None,
            }
        }
    }
}

mod flow {
    use super::analyzer::TcpAnalyzer;

    use gpc_core::base::flow::Flow;
    use gpc_core::packet::Direction;

    pub enum Handshake {
        Send,
        Recv,
        Established,
    }

    pub struct TcpFlow {
        pub handshake: Handshake,
    }

    impl Flow<TcpAnalyzer> for TcpFlow {
        fn create(_analyzer: &TcpAnalyzer, _direction: Direction) -> Self {
            TcpFlow {
                handshake: Handshake::Send,
            }
        }

        fn update(&mut self, _analyzer: &TcpAnalyzer, _direction: Direction) {
            //TODO
        }
    }
}

pub mod expression {
    use super::analyzer::TcpAnalyzer;
    use super::flow::TcpFlow;

    use crate::ClassifierId;

    use gpc_core::base::expression_value::ExpressionValue;

    #[derive(Debug)]
    pub struct Tcp;

    impl ExpressionValue<ClassifierId> for Tcp {
        type Builder = super::TcpBuilder;

        fn description() -> &'static str {
            "Valid if the packet is TCP"
        }

        fn check(&self, _analyzer: &TcpAnalyzer, _flow: &TcpFlow) -> bool {
            true
        }
    }

    #[derive(Debug)]
    pub struct TcpSourcePort(pub u16);

    impl ExpressionValue<ClassifierId> for TcpSourcePort {
        type Builder = super::TcpBuilder;

        fn description() -> &'static str {
            "Valid if the source TCP port of the packet matches the given port"
        }

        fn check(&self, analyzer: &TcpAnalyzer, _flow: &TcpFlow) -> bool {
            self.0 == analyzer.source_port
        }
    }

    #[derive(Debug)]
    pub struct TcpDestPort(pub u16);

    impl ExpressionValue<ClassifierId> for TcpDestPort {
        type Builder = super::TcpBuilder;

        fn description() -> &'static str {
            "Valid if the destination TCP port of the packet matches the given port"
        }

        fn check(&self, analyzer: &TcpAnalyzer, _flow: &TcpFlow) -> bool {
            self.0 == analyzer.dest_port
        }
    }
}
