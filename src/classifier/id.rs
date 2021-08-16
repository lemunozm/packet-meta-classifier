pub trait ClassifierIdTrait:
    From<usize> + Into<usize> + Copy + Eq + std::hash::Hash + std::fmt::Debug + Ord + 'static
{
    const NONE: Self;
    const INITIAL: Self;
    const TOTAL: usize;

    fn inner(self) -> usize {
        self.into()
    }
}
