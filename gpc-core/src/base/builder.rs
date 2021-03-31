use crate::base::analyzer::Analyzer;
use crate::base::id::ClassifierId;

pub trait Builder<I: ClassifierId>: Sized {
    type Analyzer: Analyzer<I>;
}
