use crate::Config;

use pmc_core::base::classifier::Classifier;

pub struct UdpClassifier;
impl<'a> Classifier<'a, Config> for UdpClassifier {
    type Analyzer = analyzer::UdpAnalyzer<'a>;
}

mod analyzer {
    use super::flow::UdpFlow;

    use crate::{ClassifierId, Config, FlowSignature};

    use pmc_core::base::analyzer::{Analyzer, AnalyzerInfo, AnalyzerResult, BuildFlow};
    use pmc_core::packet::{Direction, Packet};

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

        pub fn payload_len(&self) -> u16 {
            self.payload_len
        }

        fn expected_l7_classifier(_server_port: u16) -> ClassifierId {
            ClassifierId::None
        }
    }

    impl<'a> Analyzer<'a, Config> for UdpAnalyzer<'a> {
        const ID: ClassifierId = ClassifierId::Udp;
        const PREV_ID: ClassifierId = ClassifierId::Ip;

        type Flow = UdpFlow;

        fn update_flow_id(
            signature: &mut FlowSignature,
            &Packet { data, direction }: &Packet,
        ) -> BuildFlow {
            let (source, dest) = (
                u16::from_be_bytes(*array_ref![data, 0, 2]),
                u16::from_be_bytes(*array_ref![data, 2, 2]),
            );

            let (first, second) = match direction {
                Direction::Uplink => (source, dest),
                Direction::Downlink => (dest, source),
            };

            signature.client_port = first;
            signature.server_port = second;

            BuildFlow::Yes
        }

        fn build(
            _config: &Config,
            &Packet { data, direction }: &'a Packet,
            _flow: &UdpFlow,
        ) -> AnalyzerResult<Self, ClassifierId> {
            let header_len = 8;
            let payload_len = u16::from_be_bytes(*array_ref![data, 4, 2]) - header_len as u16;

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

        fn update_flow(&self, _config: &Config, _flow: &mut UdpFlow, _direction: Direction) {}
    }
}

mod flow {
    #[derive(Default)]
    pub struct UdpFlow {}
}

pub mod expression {
    use super::analyzer::UdpAnalyzer;
    use super::flow::UdpFlow;
    use super::UdpClassifier;

    use crate::Config;

    use pmc_core::base::expression_value::ExpressionValue;

    use std::fmt;

    #[derive(Debug)]
    pub struct Udp;
    impl ExpressionValue<Config> for Udp {
        type Classifier = UdpClassifier;

        const SHOULD_GRANT_BY_FLOW: bool = true;

        fn check(&self, _packet: &UdpAnalyzer, _flow: &UdpFlow) -> bool {
            true
        }
    }

    #[derive(Debug)]
    pub struct UdpSourcePort(pub u16);
    impl ExpressionValue<Config> for UdpSourcePort {
        type Classifier = UdpClassifier;

        const SHOULD_GRANT_BY_FLOW: bool = true;

        fn check(&self, packet: &UdpAnalyzer, _flow: &UdpFlow) -> bool {
            self.0 == packet.source_port()
        }
    }

    #[derive(Debug)]
    pub struct UdpDestPort(pub u16);
    impl ExpressionValue<Config> for UdpDestPort {
        type Classifier = UdpClassifier;

        const SHOULD_GRANT_BY_FLOW: bool = true;

        fn check(&self, packet: &UdpAnalyzer, _flow: &UdpFlow) -> bool {
            self.0 == packet.dest_port()
        }
    }

    pub struct UdpPayloadLen<F>(pub F);
    impl<F> fmt::Debug for UdpPayloadLen<F> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
            write!(f, "UdpPayloadLen(USER_FN)")
        }
    }
    impl<F> ExpressionValue<Config> for UdpPayloadLen<F>
    where
        F: Fn(u16) -> bool + 'static,
    {
        type Classifier = UdpClassifier;

        fn check(&self, packet: &UdpAnalyzer, _flow: &UdpFlow) -> bool {
            self.0(packet.payload_len())
        }
    }
}
