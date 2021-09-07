use crate::base::analyzer::Analyzer;
use crate::base::classifier::Classifier;
use crate::base::expression_value::ExpressionValue;
use crate::base::id::ClassifierId;
use crate::controller::analyzer::AnalyzerController;
use crate::controller::flow::FlowController;

use std::fmt;

pub trait ExpressionValueController<I: ClassifierId>: fmt::Debug {
    fn check(
        &self,
        analyzer: &dyn AnalyzerController<I>,
        flow: Option<&dyn FlowController>,
    ) -> bool;
    fn classifier_id(&self) -> I;
}

impl<I: ClassifierId> dyn ExpressionValueController<I> {
    pub fn new<V, C>(expression_value: V) -> Box<dyn ExpressionValueController<I>>
    where
        V: ExpressionValue<I, Classifier = C> + 'static,
        C: for<'a> Classifier<'a, I>,
    {
        Box::new(ControllerImpl(expression_value))
    }
}

struct ControllerImpl<V>(V);

impl<V: fmt::Debug> fmt::Debug for ControllerImpl<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl<V, C, I> ExpressionValueController<I> for ControllerImpl<V>
where
    V: ExpressionValue<I, Classifier = C>,
    C: for<'a> Classifier<'a, I>,
    I: ClassifierId,
{
    fn check(
        &self,
        analyzer: &dyn AnalyzerController<I>,
        flow: Option<&dyn FlowController>,
    ) -> bool {
        let analyzer = analyzer.inner_ref::<C::Analyzer>();

        match flow {
            Some(flow) => {
                let inner_flow = flow.inner_ref::<<C::Analyzer as Analyzer<I>>::Flow>();
                self.0.check(analyzer, inner_flow)
            }
            None => {
                let no_flow = <<C::Analyzer as Analyzer<I>>::Flow>::default();
                self.0.check(analyzer, &no_flow)
            }
        }
    }

    fn classifier_id(&self) -> I {
        C::Analyzer::ID
    }
}
