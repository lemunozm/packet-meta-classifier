use crate::base::analyzer::Analyzer;
use crate::base::id::ClassifierId;
use crate::handler::flow::{GenericFlowHandler, SharedGenericFlowHandler};
use crate::packet::Direction;

pub trait GenericAnalyzerHandler<'a, I: ClassifierId> {
    fn id(&self) -> I;
    fn prev_id(&self) -> I;
    fn update_flow_id(&self, flow_id: &mut I::FlowId, direction: Direction) -> bool;
    fn create_flow(&self, direction: Direction) -> SharedGenericFlowHandler;
    fn update_flow(&self, flow: &mut dyn GenericFlowHandler, direction: Direction);
}

impl<'a, I: ClassifierId> dyn GenericAnalyzerHandler<'a, I> + '_ {
    pub fn inner_ref<A>(&self) -> &A
    where
        A: Analyzer<'a, I>,
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
            &*(self as *const dyn GenericAnalyzerHandler<I> as *const AnalyzerHandler<A>)
        };

        &handler.0
    }
}

pub struct AnalyzerHandler<A>(pub A);

impl<A> AnalyzerHandler<A> {
    pub fn new(analyzer: A) -> Self {
        AnalyzerHandler(analyzer)
    }
}

impl<'a, A, I> GenericAnalyzerHandler<'a, I> for AnalyzerHandler<A>
where
    A: Analyzer<'a, I>,
    I: ClassifierId,
{
    fn id(&self) -> I {
        A::ID
    }

    fn prev_id(&self) -> I {
        A::PREV_ID
    }

    fn update_flow_id(&self, mut signature: &mut I::FlowId, direction: Direction) -> bool {
        self.0.update_flow_id(&mut signature, direction)
    }

    fn create_flow(&self, direction: Direction) -> SharedGenericFlowHandler {
        let flow = A::create_flow(&self.0, direction);
        <dyn GenericFlowHandler>::new_shared(flow)
    }

    fn update_flow(&self, flow: &mut dyn GenericFlowHandler, direction: Direction) {
        let flow = &mut flow.inner_mut::<A::Flow>();
        &self.0.update_flow(flow, direction);
    }
}
