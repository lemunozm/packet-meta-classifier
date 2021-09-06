use std::fmt::Debug;
use std::hash::Hash;

pub trait ClassifierId:
    From<usize> + Into<usize> + Hash + Debug + Copy + Eq + Ord + 'static
{
    const NONE: Self;
    const INITIAL: Self;
    const TOTAL: usize;

    type FlowId: Default + Clone + Hash + Eq + Debug;

    fn inner(self) -> usize {
        self.into()
    }
}
