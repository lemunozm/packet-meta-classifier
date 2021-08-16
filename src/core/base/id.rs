pub trait ClassifierId:
    From<usize> + Into<usize> + std::hash::Hash + std::fmt::Debug + Copy + Eq + Ord + 'static
{
    const NONE: Self;
    const INITIAL: Self;
    const TOTAL: usize;

    fn inner(self) -> usize {
        self.into()
    }
}
