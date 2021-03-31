use crate::base::analyzer::Analyzer;
use crate::base::builder::Builder;
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

impl<I: ClassifierId> dyn GenericExpressionValueHandler<I> {
    pub fn new<V: ExpressionValue<I> + 'static>(
        expression_value: V,
    ) -> Box<dyn GenericExpressionValueHandler<I>> {
        Box::new(ExpressionValueHandler(expression_value))
    }
}

struct ExpressionValueHandler<V>(V);

impl<V: fmt::Debug> fmt::Debug for ExpressionValueHandler<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl<V, B, A, F, I> GenericExpressionValueHandler<I> for ExpressionValueHandler<V>
where
    V: ExpressionValue<I, Builder = B>,
    B: Builder<I, Analyzer = A, Flow = F>,
    A: Analyzer<I>,
    F: Flow<A>,
    I: ClassifierId,
{
    fn check(
        &self,
        analyzer: &dyn GenericAnalyzerHandler<I>,
        flow: Option<&dyn GenericFlowHandler>,
    ) -> bool {
        let analyzer = analyzer.inner_ref::<A, F>();

        match flow {
            Some(flow) => self.0.check(analyzer, flow.inner_ref::<F>()),
            None => {
                // The flow created here is always a NoFlow
                let no_flow = F::create(&analyzer, Direction::Uplink);
                self.0.check(analyzer, &no_flow)
            }
        }
    }

    fn classifier_id(&self) -> I {
        A::ID
    }
}
