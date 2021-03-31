use crate::handler::flow::{FlowHandler, SharedGenericFlowHandler};

use crate::base::analyzer::{AnalysisResult, Analyzer};
use crate::base::flow::Flow;
use crate::base::id::ClassifierId;

use crate::packet::{Direction, Packet};

use std::cell::RefCell;
use std::rc::Rc;

pub trait GenericAnalyzerHandler<'a, I: ClassifierId> {
    fn id(&self) -> I;
    fn prev_id(&self) -> I;
    fn update_flow_signature(&self, current_signature: &mut Vec<u8>, direction: Direction) -> bool;
    fn create_flow(&self, direction: Direction) -> SharedGenericFlowHandler<I>;
    fn analyze(packet: &'a Packet) -> Option<AnalysisResult<Self, I>>
    where
        Self: Sized;
}

impl<'a, I: ClassifierId> dyn GenericAnalyzerHandler<'a, I> + '_ {
    pub fn inner_ref<B: Analyzer<'a, I>>(&self) -> &B {
        if self.id() == B::ID {
            let handler = unsafe {
                // SAFETY: Only one analyzer per ID can be registered, so if the IDs are equals
                // they are the same object.
                &*(&*self as *const dyn GenericAnalyzerHandler<'a, I> as *const AnalyzerHandler<B>)
            };
            return &handler.analyzer;
        }

        panic!(
            "Trying to cast analyzer of type {:?} into {:?}",
            self.id(),
            B::ID
        );
    }
}

pub struct AnalyzerHandler<A> {
    analyzer: A,
}

impl<'a, A, F, I> GenericAnalyzerHandler<'a, I> for AnalyzerHandler<A>
where
    F: Flow<A, I> + 'static,
    A: for<'b> Analyzer<'b, I, Flow = F>,
    I: ClassifierId,
{
    fn id(&self) -> I {
        A::ID
    }

    fn prev_id(&self) -> I {
        A::PREV_ID
    }

    fn analyze(packet: &'a Packet) -> Option<AnalysisResult<Self, I>> {
        A::analyze(packet).map(
            |AnalysisResult {
                 analyzer,
                 next_id,
                 bytes,
             }| {
                AnalysisResult {
                    analyzer: Self { analyzer },
                    next_id,
                    bytes,
                }
            },
        )
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
