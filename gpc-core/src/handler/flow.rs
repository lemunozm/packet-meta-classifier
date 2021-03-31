use crate::base::analyzer::Analyzer;
use crate::base::flow::Flow;
use crate::base::id::ClassifierId;
use crate::handler::analyzer::GenericAnalyzerHandler;
use crate::packet::Direction;

use std::cell::RefCell;
use std::rc::Rc;

pub type SharedGenericFlowHandler<'a, I> = Rc<RefCell<dyn GenericFlowHandler<I> + 'a>>;

pub trait GenericFlowHandler<I: ClassifierId> {
    fn update(&mut self, analyzer: &dyn GenericAnalyzerHandler<I>, direction: Direction);
    fn as_any(&self) -> &dyn std::any::Any;
}

pub struct FlowHandler<F, A> {
    flow: F,
    _analyzer_type: std::marker::PhantomData<A>,
}

impl<F, A> FlowHandler<F, A> {
    pub fn new(flow: F) -> Self {
        Self {
            flow,
            _analyzer_type: std::marker::PhantomData::default(),
        }
    }

    pub fn flow(&self) -> &F {
        &self.flow
    }
}

impl<F, A, I> GenericFlowHandler<I> for FlowHandler<F, A>
where
    F: Flow<A, I> + 'static,
    A: for<'a> Analyzer<'a, I>,
    I: ClassifierId,
{
    fn update(&mut self, analyzer: &dyn GenericAnalyzerHandler<I>, direction: Direction) {
        let this_analyzer = analyzer.inner_ref::<A>();
        self.flow.update(this_analyzer, direction);
    }

    fn as_any(&self) -> &dyn std::any::Any {
        //self
        todo!()
    }
}
