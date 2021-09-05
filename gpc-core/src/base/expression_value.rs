use crate::base::analyzer::Analyzer;
use crate::base::builder::Builder;
use crate::base::id::ClassifierId;

pub trait ExpressionValue<I: ClassifierId>: Sized + std::fmt::Debug + 'static {
    type Builder: for<'a> Builder<'a, I>;
    fn description() -> &'static str;
    fn check<'a>(
        &self,
        analyzer: &<Self::Builder as Builder<I>>::Analyzer,
        flow: &<<Self::Builder as Builder<'a, I>>::Analyzer as Analyzer<'a, I>>::Flow,
    ) -> bool;
}
