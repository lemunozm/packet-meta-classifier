pub mod analyzer {
    use super::flow::TcpFlow;
    use crate::ClassifierId;

    use gpc_core::base::analyzer::{Analyzer, AnalyzerStatus};
    use gpc_core::packet::{Direction, Packet};

    use std::io::Write;

    #[derive(Default)]
    pub struct TcpAnalyzer {
        pub source_port: u16,
        pub dest_port: u16,
    }

    impl Analyzer<ClassifierId> for TcpAnalyzer {
        type Flow = TcpFlow;
        const ID: ClassifierId = ClassifierId::Tcp;
        const PREV_ID: ClassifierId = ClassifierId::Ip;

        fn analyze(&mut self, packet: &Packet) -> AnalyzerStatus<ClassifierId> {
            self.source_port = u16::from_be_bytes(*array_ref![packet.data, 0, 2]);
            self.dest_port = u16::from_be_bytes(*array_ref![packet.data, 2, 2]);

            let header_len = (((packet.data[12] & 0xF0) as usize) >> 4) << 2;

            let server_port = match packet.direction {
                Direction::Uplink => self.dest_port,
                Direction::Downlink => self.source_port,
            };

            if packet.data.len() - header_len > 0 {
                if let Some(next_protocol) = Self::expected_l7_protocol(server_port) {
                    return AnalyzerStatus::Next(next_protocol, header_len);
                }
            }
            AnalyzerStatus::Finished(header_len)
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
        fn expected_l7_protocol(server_port: u16) -> Option<ClassifierId> {
            let id = match server_port {
                80 => ClassifierId::Http,
                8080 => ClassifierId::Http,
                _ => return None,
            };
            Some(id)
        }
    }
}

pub mod flow {
    use super::analyzer::TcpAnalyzer;
    use crate::ClassifierId;

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

    impl Flow<ClassifierId> for TcpFlow {
        type Analyzer = TcpAnalyzer;

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
        type Analyzer = TcpAnalyzer;

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
        type Analyzer = TcpAnalyzer;

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
        type Analyzer = TcpAnalyzer;

        fn description() -> &'static str {
            "Valid if the destination TCP port of the packet matches the given port"
        }

        fn check(&self, analyzer: &TcpAnalyzer, _flow: &TcpFlow) -> bool {
            self.0 == analyzer.dest_port
        }
    }
}
