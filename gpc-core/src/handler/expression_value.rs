use crate::base::analyzer::Analyzer;
use crate::base::classifier::Classifier;
use crate::base::expression_value::ExpressionValue;
use crate::base::id::ClassifierId;
use crate::handler::analyzer::GenericAnalyzerHandler;
use crate::handler::flow::GenericFlowHandler;

use std::fmt;
use std::mem::MaybeUninit;

pub trait GenericExpressionValueHandler<I: ClassifierId>: fmt::Debug {
    fn check(
        &self,
        analyzer: &dyn GenericAnalyzerHandler<I>,
        flow: Option<&dyn GenericFlowHandler>,
    ) -> bool;
    fn classifier_id(&self) -> I;
}

impl<I: ClassifierId> dyn GenericExpressionValueHandler<I> {
    pub fn new<V, C>(expression_value: V) -> Box<dyn GenericExpressionValueHandler<I>>
    where
        V: ExpressionValue<I, Classifier = C> + 'static,
        C: for<'a> Classifier<'a, I>,
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

impl<V, C, I> GenericExpressionValueHandler<I> for ExpressionValueHandler<V>
where
    V: ExpressionValue<I, Classifier = C>,
    C: for<'a> Classifier<'a, I>,
    I: ClassifierId,
{
    fn check(
        &self,
        analyzer: &dyn GenericAnalyzerHandler<I>,
        flow: Option<&dyn GenericFlowHandler>,
    ) -> bool {
        let analyzer = analyzer.inner_ref::<C::Analyzer>();

        match flow {
            Some(flow) => {
                let inner_flow = flow.inner_ref::<<C::Analyzer as Analyzer<I>>::Flow>();
                self.0.check(analyzer, inner_flow)
            }
            None => {
                // The flow created here should be an empty Flow.
                if std::mem::size_of::<<C::Analyzer as Analyzer<I>>::Flow>() != 0 {
                    panic!("Unexpected real flow, expected flow with no size")
                }
                let no_flow = unsafe {
                    //SAFETY: 0 sized types are safe to be uninitialized.
                    MaybeUninit::<<C::Analyzer as Analyzer<I>>::Flow>::uninit().assume_init()
                };
                self.0.check(analyzer, &no_flow)
            }
        }
    }

    fn classifier_id(&self) -> I {
        C::Analyzer::ID
    }
}
