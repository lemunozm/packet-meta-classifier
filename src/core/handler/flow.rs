use super::analyzer::{AnalyzerHandler, GenericAnalyzerHandler};

use crate::core::base::flow::Flow;
use crate::core::base::id::ClassifierId;
use crate::core::packet::Direction;

pub trait GenericFlowHandler<I: ClassifierId> {
    fn update(&mut self, analyzer: &dyn GenericAnalyzerHandler<I>, direction: Direction);
    fn as_any(&self) -> &dyn std::any::Any;
}

pub struct FlowHandler<F> {
    flow: F,
}

impl<F> FlowHandler<F> {
    pub fn new(flow: F) -> Self {
        Self { flow }
    }

    pub fn flow(&self) -> &F {
        &self.flow
    }
}

impl<F, A, I> GenericFlowHandler<I> for FlowHandler<F>
where
    F: Flow<I, Analyzer = A>,
    A: 'static,
    I: ClassifierId,
{
    fn update(&mut self, analyzer: &dyn GenericAnalyzerHandler<I>, direction: Direction) {
        let this_analyzer = analyzer
            .as_any()
            .downcast_ref::<AnalyzerHandler<F::Analyzer>>()
            .unwrap()
            .analyzer();

        self.flow.update(this_analyzer, direction);
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
