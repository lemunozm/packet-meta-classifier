use crate::base::analyzer::Analyzer;
use crate::base::id::ClassifierId;

pub trait Builder<'a, I: ClassifierId>: Sized {
    type Analyzer: Analyzer<'a, I>;
}
