use super::analyzer::Analyzer;
use super::id::ClassifierId;

pub trait ExpressionValue<I: ClassifierId>: std::fmt::Debug + 'static {
    type Analyzer: Analyzer<I>;

    fn description() -> &'static str;
    fn check(
        &self,
        analyzer: &Self::Analyzer,
        flow: &<Self::Analyzer as Analyzer<I>>::Flow,
    ) -> bool;
}
