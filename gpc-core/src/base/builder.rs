use crate::base::analyzer::Analyzer;
use crate::base::flow::Flow;
use crate::base::id::ClassifierId;

pub trait Builder<'a, I: ClassifierId>: Sized {
    type Analyzer: Analyzer<'a, I>;
    type Flow: Flow<Self::Analyzer>;
}
