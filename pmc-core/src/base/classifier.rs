use crate::base::analyzer::Analyzer;
use crate::base::config::Config;

pub trait Classifier<'a, C: Config>: Sized {
    type Analyzer: Analyzer<'a, C>;
}
