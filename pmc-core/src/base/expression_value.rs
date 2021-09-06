use crate::base::analyzer::Analyzer;
use crate::base::classifier::Classifier;
use crate::base::id::ClassifierId;

pub trait ExpressionValue<I: ClassifierId>: Sized + std::fmt::Debug + 'static {
    type Classifier: for<'a> Classifier<'a, I>;
    fn description() -> &'static str;
    fn check<'a>(
        &self,
        analyzer: &<Self::Classifier as Classifier<I>>::Analyzer,
        flow: &<<Self::Classifier as Classifier<'a, I>>::Analyzer as Analyzer<'a, I>>::Flow,
    ) -> bool;
}
