pub mod analyzer {
    use crate::analyzer::{Analyzer, AnalyzerStatus};
    use crate::classifiers::ClassifierId;
    use crate::flow::{FlowDef, GenericFlow};

    #[derive(Default)]
    pub struct TcpAnalyzer {
        pub source_port: u16,
        pub dest_port: u16,
    }

    impl Analyzer for TcpAnalyzer {
        fn analyze<'a>(&mut self, data: &'a [u8]) -> AnalyzerStatus<'a> {
            self.source_port = u16::from_be_bytes(*array_ref![data, 0, 2]);
            self.dest_port = u16::from_be_bytes(*array_ref![data, 2, 2]);

            let header_length = (((data[12] & 0xF0) as usize) >> 4) << 2;

            if self.source_port == 80 || self.source_port == 8080 {
                //AnalyzerStatus::Next(AnalyzerId::Http, data[header_length..])
                AnalyzerStatus::Finished(&data[header_length..])
            } else {
                AnalyzerStatus::Finished(&data[header_length..])
            }
        }

        fn next_classifiers() -> Vec<ClassifierId>
        where
            Self: Sized,
        {
            vec![ClassifierId::Http]
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
    }
}

pub mod flow {
    use super::analyzer::TcpAnalyzer;

    use crate::flow::Flow;

    pub enum State {
        Send,
        Recv,
        Established,
    }

    impl Default for State {
        fn default() -> Self {
            State::Send
        }
    }

    #[derive(Default)]
    pub struct TcpFlow {
        pub state: State,
    }

    impl Flow for TcpFlow {
        type Analyzer = TcpAnalyzer;
        fn update(&mut self, analyzer: &Self::Analyzer) {}
    }
}

pub mod rules {
    use super::analyzer::TcpAnalyzer;
    use super::flow::TcpFlow;

    use crate::rule::RuleValue;

    #[derive(Debug)]
    pub struct Tcp;

    impl RuleValue for Tcp {
        type Flow = TcpFlow;
        type Analyzer = TcpAnalyzer;

        fn check(&self, _analyzer: &Self::Analyzer, _flow: &Self::Flow) -> bool {
            true
        }
    }

    #[derive(Debug)]
    pub struct TcpSourcePort(pub u16);

    impl RuleValue for TcpSourcePort {
        type Flow = TcpFlow;
        type Analyzer = TcpAnalyzer;

        fn check(&self, analyzer: &Self::Analyzer, _flow: &Self::Flow) -> bool {
            self.0 == analyzer.source_port
        }
    }

    #[derive(Debug)]
    pub struct TcpDestPort(pub u16);

    impl RuleValue for TcpDestPort {
        type Flow = TcpFlow;
        type Analyzer = TcpAnalyzer;

        fn check(&self, analyzer: &Self::Analyzer, _flow: &Self::Flow) -> bool {
            self.0 == analyzer.dest_port
        }
    }
}
