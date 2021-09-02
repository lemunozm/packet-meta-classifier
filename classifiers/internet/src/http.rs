use crate::ClassifierId;

use gpc_core::base::builder::Builder;

pub struct HttpBuilder;
impl<'a> Builder<'a, ClassifierId> for HttpBuilder {
    type Analyzer = analyzer::HttpAnalyzer<'a>;
    type Flow = flow::HttpFlow;
}

mod analyzer {
    use crate::ClassifierId;

    use gpc_core::base::analyzer::{Analyzer, AnalyzerInfo, AnalyzerResult};
    use gpc_core::packet::{Direction, Packet};

    use std::io::Write;

    #[derive(Default)]
    pub struct HttpAnalyzer<'a> {
        _header: &'a [u8],
    }

    impl<'a> Analyzer<'a, ClassifierId> for HttpAnalyzer<'a> {
        const ID: ClassifierId = ClassifierId::Http;
        const PREV_ID: ClassifierId = ClassifierId::Tcp;

        fn build(&Packet { data, .. }: &'a Packet) -> AnalyzerResult<Self, ClassifierId> {
            Ok(AnalyzerInfo {
                analyzer: HttpAnalyzer {
                    _header: &data[0..],
                },
                next_classifier_id: ClassifierId::None,
                bytes_parsed: 0,
            })
        }

        fn write_flow_signature(&self, _signature: impl Write, _direction: Direction) -> bool {
            true
        }
    }
}

mod flow {
    use super::analyzer::HttpAnalyzer;

    use gpc_core::base::flow::Flow;
    use gpc_core::packet::Direction;

    pub struct HttpFlow {}

    impl Flow<HttpAnalyzer<'_>> for HttpFlow {
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
        type Builder = super::HttpBuilder;

        fn description() -> &'static str {
            "Valid if the packet is HTTP"
        }

        fn check(&self, _analyzer: &HttpAnalyzer, _flow: &HttpFlow) -> bool {
            true
        }
    }
}
