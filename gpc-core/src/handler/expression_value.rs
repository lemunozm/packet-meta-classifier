use crate::base::analyzer::Analyzer;
use crate::base::builder::Builder;
use crate::base::expression_value::ExpressionValue;
use crate::base::id::ClassifierId;
use crate::handler::analyzer::GenericAnalyzerHandler;
use crate::handler::flow::GenericFlowHandler;

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
        let analyzer = analyzer.inner_ref::<B::Analyzer>();

        match flow {
            Some(flow) => {
                let inner_flow = flow.inner_ref::<<B::Analyzer as Analyzer<I>>::Flow>();
                self.0.check(analyzer, inner_flow)
            }
            None => {
                // The flow created here should be a () Flow, so there is no cost in the creation
                let no_flow = <B::Analyzer as Analyzer<I>>::Flow::default();
                self.0.check(analyzer, &no_flow)
            }
        }
    }

    fn classifier_id(&self) -> I {
        B::Analyzer::ID
    }
}
