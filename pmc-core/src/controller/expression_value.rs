use crate::base::analyzer::Analyzer;
use crate::base::classifier::Classifier;
use crate::base::config::Config;
use crate::base::expression_value::ExpressionValue;
use crate::controller::analyzer::AnalyzerController;
use crate::controller::flow::FlowController;

use std::fmt;

pub trait ExpressionValueController<C: Config>: fmt::Debug {
    fn check(
        &self,
        analyzer: &dyn AnalyzerController<C>,
        flow: Option<&dyn FlowController>,
    ) -> bool;
    fn classifier_id(&self) -> C::ClassifierId;
}

impl<C: Config> dyn ExpressionValueController<C> {
    pub fn new<V, B>(expression_value: V) -> Box<dyn ExpressionValueController<C>>
    where
        V: ExpressionValue<C, Classifier = B> + 'static,
        B: for<'a> Classifier<'a, C>,
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

impl<V, B, C> ExpressionValueController<C> for ControllerImpl<V>
where
    V: ExpressionValue<C, Classifier = B>,
    B: for<'a> Classifier<'a, C>,
    C: Config,
{
    fn check(
        &self,
        analyzer: &dyn AnalyzerController<C>,
        flow: Option<&dyn FlowController>,
    ) -> bool {
        let analyzer = analyzer.inner_ref::<B::Analyzer>();

        match flow {
            Some(flow) => {
                let inner_flow = flow.inner_ref::<<B::Analyzer as Analyzer<C>>::Flow>();
                self.0.check(analyzer, inner_flow)
            }
            None => {
                let no_flow = <<B::Analyzer as Analyzer<C>>::Flow>::default();
                self.0.check(analyzer, &no_flow)
            }
        }
    }

    fn classifier_id(&self) -> C::ClassifierId {
        B::Analyzer::ID
    }
}
