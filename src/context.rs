use crate::analyzer::{AnalyzerPipeline};
//use crate::flow::{Flow};

pub struct Context {
    pipeline: AnalyzerPipeline,
    //flow: Option<&'a Box<dyn Flow>>,
}

impl Context {
    pub fn new(pipeline: AnalyzerPipeline, /*flow: Option<&'a Box<dyn Flow>>*/) -> Context {
        Context {
            pipeline,
            //flow,
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
