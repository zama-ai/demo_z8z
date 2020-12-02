//! A module providing a polymorphic max function.

/// A trait allowing to perform a max operation between two types.
///
/// This trait is meant to be used through the function `z8z::ops::max`. It
/// allows to retrieve the max value betweren two
pub trait Max<R> {
    type Output;
    fn max(self, rhs: R) -> Self::Output;
}

pub fn max<R, O, L: Max<R, Output = O>>(left: L, right: R) -> O {
    left.max(right)
}
