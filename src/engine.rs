use crate::configuration::{Configuration};
use crate::rules::classification::{ClassificationRules, Rule};
use crate::context::{Context};
use crate::analyzer::{AnalyzerPipeline};

pub struct ClassificationResult<'a, T> {
    pub rule: Option<&'a Rule<T, Context>>,
}

pub struct Engine<T> {
    config: Configuration,
    rules: ClassificationRules<T, Context>,
}

impl<T> Engine<T> {
    pub fn new(config: Configuration, rules: ClassificationRules<T, Context>) -> Engine<T> {
        Engine {
            config,
            rules,
        }
    }

    pub fn process_packet(&mut self, data: &[u8]) -> ClassificationResult<T> {
        let mut pipeline = AnalyzerPipeline::new();
        let data = pipeline.analyze_l3(data);
        pipeline.analyze_l4(data);

        if let Some(five_tuple) = pipeline.five_tuple() {
            //TODO: flows
        }

        let context = Context::new(pipeline);

        ClassificationResult {
            rule: self.rules.classify(&context),
        }
    }
}
