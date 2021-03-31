use crate::base::analyzer::Analyzer;
use crate::base::expression_value::ExpressionValue;
use crate::base::flow::Flow;
use crate::base::id::ClassifierId;
use crate::handler::analyzer::GenericAnalyzerHandler;
use crate::handler::flow::{FlowHandler, GenericFlowHandler};
use crate::packet::Direction;

use std::fmt;

pub trait GenericExpressionValueHandler<I: ClassifierId>: fmt::Debug {
    fn check(
        &self,
        analyzer: &dyn GenericAnalyzerHandler<I>,
        flow: Option<&dyn GenericFlowHandler<I>>,
    ) -> bool;
    fn classifier_id(&self) -> I;
}

pub struct ExpressionValueHandler<V> {
    value: V,
}

impl<V> ExpressionValueHandler<V> {
    pub fn new(value: V) -> Self {
        Self { value }
    }
}

impl<V: fmt::Debug> fmt::Debug for ExpressionValueHandler<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.value)
    }
}

impl<V, A, F, I> GenericExpressionValueHandler<I> for ExpressionValueHandler<V>
where
    V: ExpressionValue<I, Analyzer = A>,
    A: for<'a> Analyzer<'a, I, Flow = F>,
    F: Flow<A, I> + 'static,
    I: ClassifierId,
{
    fn check(
        &self,
        analyzer: &dyn GenericAnalyzerHandler<I>,
        flow: Option<&dyn GenericFlowHandler<I>>,
    ) -> bool {
        let this_analyzer = analyzer.inner_ref::<A>();

        match flow {
            Some(flow) => {
                let this_flow = flow
                    .as_any()
                    .downcast_ref::<FlowHandler<F, A>>()
                    .unwrap()
                    .flow();

                self.value.check(this_analyzer, this_flow)
            }
            None => {
                // The flow created here is always a NoFlow
                self.value
                    .check(this_analyzer, &F::create(&this_analyzer, Direction::Uplink))
            }
        }
    }

    fn classifier_id(&self) -> I {
        A::ID
    }
}
