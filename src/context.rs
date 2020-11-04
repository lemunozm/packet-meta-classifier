use crate::analyzer::{AnalyzerPipeline};

pub struct Context {
    pipeline: AnalyzerPipeline,
}

impl Context {
    pub fn new(pipeline: AnalyzerPipeline) -> Context {
        Context {
            pipeline
        }
    }

    pub fn pipeline(&self) -> &AnalyzerPipeline {
        &self.pipeline
    }
}
