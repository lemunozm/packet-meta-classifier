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
    pub fn new<V, B>(expression_value: V) -> Box<dyn GenericExpressionValueHandler<I>>
    where
        V: ExpressionValue<I, Builder = B> + 'static,
        B: for<'a> Builder<'a, I>,
    {
        Box::new(ExpressionValueHandler(expression_value))
    }
}

struct ExpressionValueHandler<V>(V);

impl<V: fmt::Debug> fmt::Debug for ExpressionValueHandler<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl<V, B, I> GenericExpressionValueHandler<I> for ExpressionValueHandler<V>
where
    V: ExpressionValue<I, Builder = B>,
    B: for<'a> Builder<'a, I>,
    I: ClassifierId,
{
    fn check(
        &self,
        analyzer: &dyn GenericAnalyzerHandler<I>,
        flow: Option<&dyn GenericFlowHandler>,
    ) -> bool {
        let analyzer = analyzer.inner_ref::<B::Analyzer, B::Flow>();

        match flow {
            Some(flow) => self.0.check(analyzer, flow.inner_ref::<B::Flow>()),
            None => {
                // The flow created here is always a NoFlow
                let no_flow = B::Flow::create(&analyzer, Direction::Uplink);
                self.0.check(analyzer, &no_flow)
            }
        }
    }

    fn classifier_id(&self) -> I {
        B::Analyzer::ID
    }
}
