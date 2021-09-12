use crate::base::analyzer::Analyzer;
use crate::base::classifier::Classifier;
use crate::base::config::Config;

pub enum CacheMode {
    Never,
    Until(bool),
}

pub trait ExpressionValue<C: Config>: Sized + std::fmt::Debug + 'static {
    type Classifier: for<'a> Classifier<'a, C>;

    fn description() -> &'static str;

    fn cache_by_flow(_analyzer: &<Self::Classifier as Classifier<C>>::Analyzer) -> CacheMode {
        CacheMode::Never
    }

    fn check<'a>(
        &self,
        analyzer: &<Self::Classifier as Classifier<C>>::Analyzer,
        flow: &<<Self::Classifier as Classifier<'a, C>>::Analyzer as Analyzer<'a, C>>::Flow,
    ) -> bool;
}
