use crate::base::analyzer::{Analyzer, BuildFlow};
use crate::base::config::Config;
use crate::controller::flow::{FlowController, SharedFlowController};
use crate::packet::{Direction, Packet};

pub trait AnalyzerController<'a, C: Config> {
    fn id(&self) -> C::ClassifierId;
    fn prev_id(&self) -> C::ClassifierId;
    fn update_flow_id(&self, flow_id: &mut C::FlowId, packet: &Packet) -> BuildFlow;
    fn create_flow(&self) -> SharedFlowController;
    fn update_flow(&self, config: &C, flow: &mut dyn FlowController, direction: Direction);
}

impl<'a, C: Config> dyn AnalyzerController<'a, C> + '_ {
    pub fn inner_ref<A>(&self) -> &A
    where
        A: Analyzer<'a, C>,
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
            &*(self as *const dyn AnalyzerController<C> as *const AnalyzerControllerImpl<A>)
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

impl<'a, A, C> AnalyzerController<'a, C> for AnalyzerControllerImpl<A>
where
    A: Analyzer<'a, C>,
    C: Config,
{
    fn id(&self) -> C::ClassifierId {
        A::ID
    }

    fn prev_id(&self) -> C::ClassifierId {
        A::PREV_ID
    }

    fn update_flow_id(&self, mut flow_id: &mut C::FlowId, packet: &Packet) -> BuildFlow {
        A::update_flow_id(&mut flow_id, packet)
    }

    fn create_flow(&self) -> SharedFlowController {
        let flow = A::Flow::default();
        <dyn FlowController>::new_shared(flow)
    }

    fn update_flow(&self, config: &C, flow: &mut dyn FlowController, direction: Direction) {
        let flow = &mut flow.inner_mut::<A::Flow>();
        self.0.update_flow(config, flow, direction);
    }
}
