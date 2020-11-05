use crate::configuration::{Configuration};
use crate::rules::classification::{ClassificationRules, Rule};
use crate::context::{Context};
use crate::analyzer::{AnalyzerPipeline};
use crate::flow::{FlowManager};

pub struct ClassificationResult<'a, T> {
    pub rule: Option<&'a Rule<T, Context>>,
}

pub struct Engine<T> {
    config: Configuration,
    rules: ClassificationRules<T, Context>,
    flow_manager: FlowManager,
}

impl<T> Engine<T> {
    pub fn new(config: Configuration, rules: ClassificationRules<T, Context>) -> Engine<T> {
        Engine {
            config,
            rules,
            flow_manager: FlowManager::new(),
        }
    }

    pub fn process_packet(&mut self, data: &[u8]) -> ClassificationResult<T> {
        let mut pipeline = AnalyzerPipeline::new();
        let data = pipeline.analyze_l3(data);
        pipeline.analyze_l4(data);

        let flow = match pipeline.five_tuple() {
            Some(five_tuple) => {
                let flow = self.flow_manager.get_or_create(five_tuple);
                flow.update(&pipeline.l4());
                Some(&*flow)
            },
            None => None
        };

        let context = Context::new(pipeline, /*flow*/);
        ClassificationResult {
            rule: self.rules.classify(&context),
        }
    }
}
