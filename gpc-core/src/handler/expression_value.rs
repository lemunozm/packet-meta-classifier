use crate::base::analyzer::Analyzer;
use crate::base::expression_value::ExpressionValue;
use crate::base::flow::Flow;
use crate::base::id::ClassifierId;
use crate::handler::analyzer::GenericAnalyzerHandler;
use crate::handler::flow::GenericFlowHandler;
use crate::packet::Direction;

use std::fmt;

pub trait GenericExpressionValueHandler<I: ClassifierId>: fmt::Debug {
    fn check(
        &self,
        analyzer: &dyn GenericAnalyzerHandler<I>,
        flow: Option<&dyn GenericFlowHandler>,
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
    A: Analyzer<I, Flow = F>,
    F: Flow<A>,
    I: ClassifierId,
{
    fn check(
        &self,
        analyzer: &dyn GenericAnalyzerHandler<I>,
        flow: Option<&dyn GenericFlowHandler>,
    ) -> bool {
        let analyzer = analyzer.inner_ref::<A>();

        match flow {
            Some(flow) => self.value.check(analyzer, flow.inner_ref::<F>()),
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
