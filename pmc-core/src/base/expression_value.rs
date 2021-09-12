use crate::base::analyzer::Analyzer;
use crate::base::classifier::Classifier;
use crate::base::config::Config;

pub trait ExpressionValue<C: Config>: Sized + std::fmt::Debug + 'static {
    type Classifier: for<'a> Classifier<'a, C>;

    const SHOULD_GRANT_BY_FLOW: bool = false;

    fn should_break_grant(
        &self,
        _analyzer: &<Self::Classifier as Classifier<C>>::Analyzer,
    ) -> bool {
        false
    }

    fn check<'a>(
        &self,
        analyzer: &<Self::Classifier as Classifier<C>>::Analyzer,
        flow: &<<Self::Classifier as Classifier<'a, C>>::Analyzer as Analyzer<'a, C>>::Flow,
    ) -> bool;
}
