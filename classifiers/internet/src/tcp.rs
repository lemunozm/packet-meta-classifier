use crate::ClassifierId;

use gpc_core::base::builder::Builder;

pub struct TcpBuilder;
impl<'a> Builder<'a, ClassifierId> for TcpBuilder {
    type Analyzer = analyzer::TcpAnalyzer<'a>;
}

mod analyzer {
    use super::flow::{Handshake, TcpFlow};

    use crate::ClassifierId;

    use gpc_core::base::analyzer::{Analyzer, AnalyzerInfo, AnalyzerResult};
    use gpc_core::packet::{Direction, Packet};

    use std::io::Write;

    pub struct TcpAnalyzer<'a> {
        pub header: &'a [u8],
        pub payload_len: u16,
    }

    impl<'a> TcpAnalyzer<'a> {
        pub fn source_port(&self) -> u16 {
            u16::from_be_bytes(*array_ref![self.header, 0, 2])
        }

        pub fn dest_port(&self) -> u16 {
            u16::from_be_bytes(*array_ref![self.header, 2, 2])
        }

        fn expected_l7_classifier(server_port: u16) -> ClassifierId {
            match server_port {
                80 => ClassifierId::Http,
                8080 => ClassifierId::Http,
                _ => ClassifierId::None,
            }
        }
    }

    impl<'a> Analyzer<'a, ClassifierId> for TcpAnalyzer<'a> {
        const ID: ClassifierId = ClassifierId::Tcp;
        const PREV_ID: ClassifierId = ClassifierId::Ip;

        type Flow = TcpFlow;

        fn build(&Packet { data, direction }: &'a Packet) -> AnalyzerResult<Self, ClassifierId> {
            let header_len = (((data[12] & 0xF0) as usize) >> 4) << 2;

            let analyzer = Self {
                header: &data[0..header_len],
                payload_len: (data.len() - header_len) as u16,
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

        fn create_flow(&self, _direction: Direction) -> TcpFlow {
            TcpFlow {
                handshake: Handshake::Send,
            }
        }

        fn update_flow(&self, _flow: &mut TcpFlow, _direction: Direction) {}
    }
}

mod flow {
    pub enum Handshake {
        Send,
        Recv,
        Established,
    }

    pub struct TcpFlow {
        pub handshake: Handshake,
    }
}

pub mod expression {
    use super::analyzer::TcpAnalyzer;
    use super::flow::TcpFlow;
    use super::TcpBuilder;

    use crate::ClassifierId;

    use gpc_core::base::expression_value::ExpressionValue;

    #[derive(Debug)]
    pub struct TcpSourcePort(pub u16);

    impl ExpressionValue<ClassifierId> for TcpSourcePort {
        type Builder = TcpBuilder;

        fn description() -> &'static str {
            "Valid if the source TCP port of the packet matches the given port"
        }

        fn check(&self, analyzer: &TcpAnalyzer, _flow: &TcpFlow) -> bool {
            self.0 == analyzer.source_port()
        }
    }

    #[derive(Debug)]
    pub struct TcpDestPort(pub u16);

    impl ExpressionValue<ClassifierId> for TcpDestPort {
        type Builder = TcpBuilder;

        fn description() -> &'static str {
            "Valid if the destination TCP port of the packet matches the given port"
        }

        fn check(&self, analyzer: &TcpAnalyzer, _flow: &TcpFlow) -> bool {
            self.0 == analyzer.dest_port()
        }
    }

    #[derive(Debug)]
    pub struct TcpPayload;

    impl ExpressionValue<ClassifierId> for TcpPayload {
        type Builder = TcpBuilder;

        fn description() -> &'static str {
            "Valid if the TCP packet contains payload"
        }

        fn check(&self, analyzer: &TcpAnalyzer, _flow: &TcpFlow) -> bool {
            analyzer.payload_len > 0
        }
    }
}
