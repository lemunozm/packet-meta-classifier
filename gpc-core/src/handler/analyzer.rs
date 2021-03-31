use crate::handler::flow::{FlowHandler, SharedGenericFlowHandler};

use crate::base::analyzer::{Analyzer, AnalyzerResult};
use crate::base::flow::Flow;
use crate::base::id::ClassifierId;

use crate::packet::{Direction, Packet};

use std::any::Any;
use std::cell::RefCell;
use std::rc::Rc;

pub enum AnalyzerStatus<I: ClassifierId> {
    Next(I, usize),
    Abort,
}

pub trait GenericAnalyzerHandler<I: ClassifierId> {
    fn id(&self) -> I;
    fn prev_id(&self) -> I;
    fn analyze(&mut self, packet: &Packet) -> AnalyzerStatus<I>;
    fn as_any(&self) -> &dyn Any;
    fn update_flow_signature(&self, current_signature: &mut Vec<u8>, direction: Direction) -> bool;
    fn create_flow(&self, direction: Direction) -> SharedGenericFlowHandler<I>;
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
        A::PREV_ID
    }

    fn analyze(&mut self, packet: &Packet) -> AnalyzerStatus<I> {
        match A::analyze(packet) {
            AnalyzerResult::Next(analyzer, id, bytes_parsed) => {
                self.analyzer = analyzer;
                AnalyzerStatus::Next(id, bytes_parsed)
            }
            AnalyzerResult::Abort => AnalyzerStatus::Abort,
        }
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn update_flow_signature(
        &self,
        mut current_signature: &mut Vec<u8>,
        direction: Direction,
    ) -> bool {
        self.analyzer
            .write_flow_signature(&mut current_signature, direction)
    }

    fn create_flow(&self, direction: Direction) -> SharedGenericFlowHandler<I> {
        Rc::new(RefCell::new(FlowHandler::new(F::create(
            &self.analyzer,
            direction,
        ))))
    }
}
