use crate::ClassifierId;
use gpc_core::base::analyzer::AnalyzerBuilder;

pub struct TcpBuilder;
impl<'a> AnalyzerBuilder<'a, ClassifierId> for TcpBuilder {
    type Analyzer = analyzer::TcpAnalyzer<'a>;
}

pub mod analyzer {
    use super::flow::TcpFlow;
    use crate::ClassifierId;

    use gpc_core::base::analyzer::{AnalysisResult, Analyzer};
    use gpc_core::packet::{Direction, Packet};

    use byteorder::{BigEndian, ByteOrder, ReadBytesExt};

    use std::io::Write;

    #[derive(Default)]
    pub struct TcpAnalyzer<'a> {
        pub header: &'a [u8],
    }

    impl<'a> Analyzer<'a, ClassifierId> for TcpAnalyzer<'a> {
        const ID: ClassifierId = ClassifierId::Tcp;
        const PREV_ID: ClassifierId = ClassifierId::Ip;
        type Flow = TcpFlow;

        fn analyze(packet: &Packet<'a>) -> Option<AnalysisResult<Self, ClassifierId>> {
            let analyzer = TcpAnalyzer {
                header: packet.data,
            };

            let next_protocol = match packet.data.len() - analyzer.header_len() > 0 {
                true => {
                    let server_port = match packet.direction {
                        Direction::Uplink => analyzer.dest_port(),
                        Direction::Downlink => analyzer.source_port(),
                    };
                    Self::expected_l7_protocol(server_port)
                }
                false => ClassifierId::None,
            };

            Some(AnalysisResult {
                analyzer,
                next_id: next_protocol,
                bytes: analyzer.header_len(),
            })
        }

        fn write_flow_signature(&self, mut signature: impl Write, direction: Direction) -> bool {
            let (first, second) = match direction {
                Direction::Uplink => (self.source_port(), self.dest_port()),
                Direction::Downlink => (self.dest_port(), self.source_port()),
            };

            signature.write_all(&first.to_le_bytes()).unwrap();
            signature.write_all(&second.to_le_bytes()).unwrap();
            true
        }
    }

    impl<'a> TcpAnalyzer<'a> {
        fn expected_l7_protocol(server_port: u16) -> ClassifierId {
            //TODO: improved performance with an static array of 2¹⁶ elements.
            match server_port {
                80 => ClassifierId::Http,
                8080 => ClassifierId::Http,
                _ => ClassifierId::None,
            }
        }

        fn header_len(&self) -> usize {
            (((self.header[12] & 0xF0) as usize) >> 4) << 2
        }

        pub fn source_port(&self) -> u16 {
            BigEndian::read_u16(&self.header[0..2])
        }

        pub fn dest_port(&self) -> u16 {
            BigEndian::read_u16(&self.header[2..4])
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
        type Analyzer = TcpAnalyzer<ClassifierId>;

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
        type Analyzer<'a> = TcpAnalyzer<'a>;

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
        type Analyzer<'a> = TcpAnalyzer<'a>;

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
        type Analyzer<'a> = TcpAnalyzer<'a>;

        fn description() -> &'static str {
            "Valid if the destination TCP port of the packet matches the given port"
        }

        fn check(&self, analyzer: &TcpAnalyzer, _flow: &TcpFlow) -> bool {
            self.0 == analyzer.dest_port()
        }
    }
}
