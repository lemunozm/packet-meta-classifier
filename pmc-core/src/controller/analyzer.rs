use crate::base::analyzer::Analyzer;
use crate::base::id::ClassifierId;
use crate::controller::flow::{FlowController, SharedFlowController};
use crate::packet::Direction;

pub trait AnalyzerController<'a, I: ClassifierId> {
    fn id(&self) -> I;
    fn prev_id(&self) -> I;
    fn update_flow_id(&self, flow_id: &mut I::FlowId, direction: Direction) -> bool;
    fn create_flow(&self, direction: Direction) -> SharedFlowController;
    fn update_flow(&self, flow: &mut dyn FlowController, direction: Direction);
}

impl<'a, I: ClassifierId> dyn AnalyzerController<'a, I> + '_ {
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

        let controller = unsafe {
            // SAFETY: Only one analyzer per ID can be registered, so if the IDs are equals
            // they are the same object.
            &*(self as *const dyn AnalyzerController<I> as *const AnalyzerControllerImpl<A>)
        };

        &controller.0
    }
}

pub struct AnalyzerControllerImpl<A>(A);

impl<A> AnalyzerControllerImpl<A> {
    pub fn new(analyzer: A) -> Self {
        AnalyzerControllerImpl(analyzer)
    }
}

impl<'a, A, I> AnalyzerController<'a, I> for AnalyzerControllerImpl<A>
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

    fn create_flow(&self, direction: Direction) -> SharedFlowController {
        let flow = A::create_flow(&self.0, direction);
        <dyn FlowController>::new_shared(flow)
    }

    fn update_flow(&self, flow: &mut dyn FlowController, direction: Direction) {
        let flow = &mut flow.inner_mut::<A::Flow>();
        self.0.update_flow(flow, direction);
    }
}
