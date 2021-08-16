use super::flow::{FlowHandler, GenericFlowHandler};

use crate::core::base::analyzer::{Analyzer, AnalyzerStatus};
use crate::core::base::flow::Flow;
use crate::core::base::id::ClassifierId;

use std::any::Any;
use std::cell::RefCell;
use std::rc::Rc;

pub trait GenericAnalyzerHandler<I: ClassifierId> {
    fn id(&self) -> I;
    fn prev_id(&self) -> I;
    fn analyze<'a>(&mut self, data: &'a [u8]) -> AnalyzerStatus<'a, I>;
    fn as_any(&self) -> &dyn Any;
    fn reset(&mut self);
    fn update_flow_signature(&self, current_signature: &mut Vec<u8>) -> bool;
    fn create_flow(&self) -> Rc<RefCell<dyn GenericFlowHandler<I>>>;
}

pub struct AnalyzerHandler<A> {
    analyzer: A,
}

impl<A> AnalyzerHandler<A> {
    pub fn new(analyzer: A) -> Self {
        Self { analyzer }
    }

    pub fn analyzer(&self) -> &A {
        &self.analyzer
    }
}

impl<A, F, I> GenericAnalyzerHandler<I> for AnalyzerHandler<A>
where
    A: Analyzer<I, Flow = F>,
    F: Flow<I, Analyzer = A>,
    I: ClassifierId,
{
    fn id(&self) -> I {
        A::ID
    }

    fn prev_id(&self) -> I {
        A::PrevAnalyzer::ID
    }

    fn analyze<'a>(&mut self, data: &'a [u8]) -> AnalyzerStatus<'a, I> {
        self.analyzer.analyze(data)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn reset(&mut self) {
        self.analyzer = A::default();
    }

    fn update_flow_signature(&self, mut current_signature: &mut Vec<u8>) -> bool {
        self.analyzer.write_flow_signature(&mut current_signature)
    }

    fn create_flow(&self) -> Rc<RefCell<dyn GenericFlowHandler<I>>> {
        Rc::new(RefCell::new(FlowHandler::new(F::create(&self.analyzer))))
    }
}
