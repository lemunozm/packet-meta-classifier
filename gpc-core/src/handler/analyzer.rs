use crate::handler::flow::{FlowHandler, GenericFlowHandler, SharedGenericFlowHandler};

use crate::base::analyzer::Analyzer;
use crate::base::flow::Flow;
use crate::base::id::ClassifierId;

use crate::packet::{Direction, Packet};

use std::cell::RefCell;
use std::rc::Rc;

pub enum AnalyzerStatus<I: ClassifierId> {
    Next(I, usize),
    Abort(&'static str),
}

pub trait GenericAnalyzerHandler<I: ClassifierId> {
    fn id(&self) -> I;
    fn prev_id(&self) -> I;
    fn analyze(&mut self, packet: &Packet) -> AnalyzerStatus<I>;
    fn update_flow_signature(&self, current_signature: &mut Vec<u8>, direction: Direction) -> bool;
    fn create_flow(&self, direction: Direction) -> SharedGenericFlowHandler;
    fn update_flow(&self, flow: &mut dyn GenericFlowHandler, direction: Direction);
}

impl<I: ClassifierId> dyn GenericAnalyzerHandler<I> + '_ {
    pub fn inner_ref<B: Analyzer<I>>(&self) -> &B {
        if self.id() == B::ID {
            let handler = unsafe {
                // SAFETY: Only one analyzer per ID can be registered, so if the IDs are equals
                // they are the same object.
                &*(&*self as *const dyn GenericAnalyzerHandler<I> as *const AnalyzerHandler<B>)
            };
            return &handler.0;
        }

        panic!(
            "Trying to cast analyzer of type {:?} into {:?}",
            self.id(),
            B::ID
        );
    }
}

pub struct AnalyzerHandler<A>(pub A);

impl<A, F, I> GenericAnalyzerHandler<I> for AnalyzerHandler<A>
where
    A: Analyzer<I, Flow = F> + 'static,
    F: Flow<A>,
    I: ClassifierId,
{
    fn id(&self) -> I {
        A::ID
    }

    fn prev_id(&self) -> I {
        A::PREV_ID
    }

    fn analyze(&mut self, packet: &Packet) -> AnalyzerStatus<I> {
        match A::build(packet) {
            Ok(info) => {
                self.0 = info.analyzer;
                AnalyzerStatus::Next(info.next_classifier_id, info.bytes_parsed)
            }
            Err(reason) => AnalyzerStatus::Abort(reason),
        }
    }

    fn update_flow_signature(&self, mut signature: &mut Vec<u8>, direction: Direction) -> bool {
        self.0.write_flow_signature(&mut signature, direction)
    }

    fn create_flow(&self, direction: Direction) -> SharedGenericFlowHandler {
        Rc::new(RefCell::new(FlowHandler(F::create(&self.0, direction))))
    }

    fn update_flow(&self, flow: &mut dyn GenericFlowHandler, direction: Direction) {
        let flow = &mut flow
            .as_mut_any()
            .downcast_mut::<FlowHandler<A::Flow>>()
            .unwrap()
            .0;

        flow.update(&self.0, direction);
    }
}
