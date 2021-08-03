pub mod analyzer {
    use crate::classifiers::AnalyzerId;
    use crate::flow::{FlowDef, GenericFlow};
    use crate::Analyzer;

    #[derive(Default)]
    pub struct IpAnalyzer {}

    impl Analyzer for IpAnalyzer {
        fn analyze<'a>(&mut self, data: &'a [u8]) -> (Option<AnalyzerId>, &'a [u8]) {
            todo!()
        }

        fn identify_flow(&self) -> Option<FlowDef> {
            todo!()
        }

        fn create_flow(&self) -> Box<dyn GenericFlow> {
            todo!()
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }
}
