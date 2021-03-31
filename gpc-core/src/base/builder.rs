use crate::base::analyzer::Analyzer;
use crate::base::flow::Flow;
use crate::base::id::ClassifierId;

pub trait Builder<I: ClassifierId>: Sized {
    type Analyzer: Analyzer<I>;
    type Flow: Flow<Self::Analyzer>;
}
