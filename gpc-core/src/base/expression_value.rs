use crate::base::builder::Builder;
use crate::base::id::ClassifierId;

pub trait ExpressionValue<I: ClassifierId>: std::fmt::Debug + 'static {
    type Builder: Builder<I>;

    fn description() -> &'static str;
    fn check(
        &self,
        analyzer: &<Self::Builder as Builder<I>>::Analyzer,
        flow: &<Self::Builder as Builder<I>>::Flow,
    ) -> bool;
}
