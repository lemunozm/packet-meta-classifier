use crate::base::analyzer::Analyzer;
use crate::base::expression_value::ExpressionValue;
use crate::base::flow::Flow;
use crate::base::id::ClassifierId;
use crate::handler::analyzer::{AnalyzerHandler, GenericAnalyzerHandler};
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
    A: Analyzer<I, Flow = F> + 'static,
    F: Flow<I, Analyzer = A>,
    I: ClassifierId,
{
    fn check(
        &self,
        analyzer: &dyn GenericAnalyzerHandler<I>,
        flow: Option<&dyn GenericFlowHandler<I>>,
    ) -> bool {
        let analyzer = analyzer
            .as_any()
            .downcast_ref::<AnalyzerHandler<A>>()
            .unwrap()
            .analyzer();

        match flow {
            Some(flow) => {
                let flow = flow
                    .as_any()
                    .downcast_ref::<FlowHandler<F>>()
                    .unwrap()
                    .flow();

                self.value.check(analyzer, flow)
            }
            None => {
                // The flow created here is always a NoFlow
                self.value
                    .check(analyzer, &F::create(&analyzer, Direction::Uplink))
            }
        }
    }

    fn classifier_id(&self) -> I {
        A::ID
    }
}
