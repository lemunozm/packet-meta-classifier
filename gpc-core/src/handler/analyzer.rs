use crate::handler::flow::{GenericFlowHandler, SharedGenericFlowHandler};

use crate::base::analyzer::Analyzer;
use crate::base::flow::Flow;
use crate::base::id::ClassifierId;

use crate::packet::Direction;

pub trait GenericAnalyzerHandler<I: ClassifierId> {
    fn id(&self) -> I;
    fn prev_id(&self) -> I;
    fn update_flow_signature(&self, current_signature: &mut Vec<u8>, direction: Direction) -> bool;
    fn create_flow(&self, direction: Direction) -> SharedGenericFlowHandler;
    fn update_flow(&self, flow: &mut dyn GenericFlowHandler, direction: Direction);
}

impl<I: ClassifierId> dyn GenericAnalyzerHandler<I> + '_ {
    pub fn inner_ref<A: Analyzer<I>>(&self) -> &A {
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

    pub fn update<A: Analyzer<I>>(&mut self, new_analyzer: A) {
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
            &mut *(self as *mut dyn GenericAnalyzerHandler<I> as *mut AnalyzerHandler<A>)
        };
        handler.0 = new_analyzer;
    }

    pub fn new<'a, A: Analyzer<I> + 'a>(analyzer: A) -> Box<dyn GenericAnalyzerHandler<I> + 'a> {
        Box::new(AnalyzerHandler(analyzer))
    }
}

struct AnalyzerHandler<A>(A);

impl<A, F, I> GenericAnalyzerHandler<I> for AnalyzerHandler<A>
where
    A: Analyzer<I, Flow = F>,
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
        let flow = &mut flow.inner_mut::<A::Flow>();
        flow.update(&self.0, direction);
    }
}
