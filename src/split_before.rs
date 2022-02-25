/// Iterator which splits a slice inclusively keeping the matched item at the start of the next returned slice.
/// The current implementation fails if the first item is matched
pub struct SplitBefore<'a, T, P>
where
    P: FnMut(&T) -> bool,
{
    v: &'a [T],
    n: &'a [T],
    pred: P,
}

impl<'a, T, P> Iterator for SplitBefore<'a, T, P>
where
    P: FnMut(&T) -> bool,
{
    type Item = &'a [T];

    fn next(&mut self) -> Option<&'a [T]> {
        if self.n.is_empty() {
            return None;
        }
        let ret = Some(self.n);

        let idx = self
            .v
            .iter()
            .skip(1)
            .position(|x| (self.pred)(x))
            .unwrap_or(self.v.len());
        self.n = &self.v[..idx];
        self.v = &self.v[idx..];
        ret
    }
}

impl<'a, T, P> SplitBefore<'a, T, P>
where
    P: FnMut(&T) -> bool,
{
    pub fn new(slice: &'a [T], mut pred: P) -> Self {
        let idx = slice.iter().position(|x| pred(x)).unwrap_or(slice.len());

        SplitBefore {
            v: &slice[idx..],
            n: &slice[..idx],
            pred,
        }
    }
}
