use crate::base::analyzer::Analyzer;
use crate::base::flow::Flow;
use crate::base::id::ClassifierId;
use crate::handler::flow::{GenericFlowHandler, SharedGenericFlowHandler};
use crate::packet::Direction;

use std::marker::PhantomData;

pub trait GenericAnalyzerHandler<'a, I: ClassifierId> {
    fn id(&self) -> I;
    fn prev_id(&self) -> I;
    fn update_flow_signature(&self, current_signature: &mut Vec<u8>, direction: Direction) -> bool;
    fn create_flow(&self, direction: Direction) -> SharedGenericFlowHandler;
    fn update_flow(&self, flow: &mut dyn GenericFlowHandler, direction: Direction);
}

impl<'a, I: ClassifierId> dyn GenericAnalyzerHandler<'a, I> + '_ {
    pub fn inner_ref<A, F>(&self) -> &A
    where
        A: Analyzer<'a, I>,
        F: Flow<A>,
    {
        if self.id() != A::ID {
            panic!(
                "Trying to cast analyzer of type {:?} into {:?}",
                self.id(),
                A::ID
            );
        }

        let handler = unsafe {
            // SAFETY: Only one analyzer per ID can be registered, so if the IDs are equals
            // they are the same object.
            &*(self as *const dyn GenericAnalyzerHandler<I> as *const AnalyzerHandler<A, F>)
        };

        &handler.0
    }
}

pub struct AnalyzerHandler<A, F>(pub A, pub PhantomData<F>);

impl<'a, A, F, I> GenericAnalyzerHandler<'a, I> for AnalyzerHandler<A, F>
where
    A: Analyzer<'a, I>,
    F: Flow<A> + 'static,
    I: ClassifierId,
{
    fn id(&self) -> I {
        A::ID
    }

    fn prev_id(&self) -> I {
        A::PREV_ID
    }

    fn update_flow_signature(&self, mut signature: &mut Vec<u8>, direction: Direction) -> bool {
        self.0.write_flow_signature(&mut signature, direction)
    }

    fn create_flow(&self, direction: Direction) -> SharedGenericFlowHandler {
        <dyn GenericFlowHandler>::new_shared(F::create(&self.0, direction))
    }

    fn update_flow(&self, flow: &mut dyn GenericFlowHandler, direction: Direction) {
        let flow = &mut flow.inner_mut::<F>();
        flow.update(&self.0, direction);
    }
}
