pub mod analyzer {
    use super::flow::HttpFlow;
    use crate::ClassifierId;

    use gpc_core::base::analyzer::{Analyzer, AnalyzerResult};
    use gpc_core::packet::{Direction, Packet};

    use std::io::Write;

    #[derive(Default)]
    pub struct HttpAnalyzer {}

    impl Analyzer<ClassifierId> for HttpAnalyzer {
        const ID: ClassifierId = ClassifierId::Http;
        const PREV_ID: ClassifierId = ClassifierId::Tcp;
        type Flow = HttpFlow;

        fn analyze(_packet: &Packet) -> AnalyzerResult<Self, ClassifierId> {
            AnalyzerResult::Next(HttpAnalyzer {}, ClassifierId::None, 0)
        }

        fn write_flow_signature(&self, _signature: impl Write, _direction: Direction) -> bool {
            true
        }
    }
}

pub mod flow {
    use super::analyzer::HttpAnalyzer;
    use crate::ClassifierId;

    use gpc_core::base::flow::Flow;
    use gpc_core::packet::Direction;

    pub enum Handshake {
        Send,
        Recv,
        Established,
    }

    pub struct HttpFlow {}

    impl Flow<ClassifierId> for HttpFlow {
        type Analyzer = HttpAnalyzer;

        fn create(_analyzer: &HttpAnalyzer, _direction: Direction) -> Self {
            HttpFlow {}
        }

        fn update(&mut self, _analyzer: &HttpAnalyzer, _direction: Direction) {
            //TODO
        }
    }
}

pub mod expression {
    use super::analyzer::HttpAnalyzer;
    use super::flow::HttpFlow;

    use crate::ClassifierId;

    use gpc_core::base::expression_value::ExpressionValue;

    #[derive(Debug)]
    pub struct Http;

    impl ExpressionValue<ClassifierId> for Http {
        type Analyzer = HttpAnalyzer;

        fn description() -> &'static str {
            "Valid if the packet is HTTP"
        }

        fn check(&self, _analyzer: &HttpAnalyzer, _flow: &HttpFlow) -> bool {
            true
        }
    }
}
