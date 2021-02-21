use crate::analyzer::{AnalyzerPipeline};
use crate::flow::{Flow};

pub struct Context<'a> {
    pipeline: AnalyzerPipeline,
    flow: Option<&'a Box<dyn Flow>>,
}

impl<'a> Context<'a> {
    pub fn new(pipeline: AnalyzerPipeline, flow: Option<&'a Box<dyn Flow>>) -> Context<'a> {
        Context {
            pipeline,
            flow,
        }
    }

    pub fn pipeline(&self) -> &AnalyzerPipeline {
        &self.pipeline
    }

    /*
    pub fn flow(&self) -> &Box<dyn Flow> {
        &self.flow
    }
    */
}
