use crate::base::analyzer::Analyzer;
use crate::base::id::ClassifierId;

pub trait Classifier<'a, I: ClassifierId>: Sized {
    type Analyzer: Analyzer<'a, I>;
}
