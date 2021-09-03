pub trait ExpressionValue<A, F>: std::fmt::Debug + 'static {
    fn description() -> &'static str;
    fn check(&self, analyzer: &A, flow: &F) -> bool;
}
