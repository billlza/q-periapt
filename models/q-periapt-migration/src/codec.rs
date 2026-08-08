//! Private fixed-width LP8 writer for the migration-context body.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CodecError {
    LengthOverflow,
    OutputTooShort,
}

pub(crate) struct Lp8Writer<'a> {
    remaining: &'a mut [u8],
}

impl<'a> Lp8Writer<'a> {
    pub(crate) const fn new(out: &'a mut [u8]) -> Self {
        Self { remaining: out }
    }

    pub(crate) fn field(&mut self, field: &[u8]) -> Result<(), CodecError> {
        let field_len = u64::try_from(field.len()).map_err(|_| CodecError::LengthOverflow)?;
        let needed = 8usize
            .checked_add(field.len())
            .ok_or(CodecError::LengthOverflow)?;
        let current = core::mem::take(&mut self.remaining);
        if current.len() < needed {
            self.remaining = current;
            return Err(CodecError::OutputTooShort);
        }
        let (encoded, tail) = current.split_at_mut(needed);
        let (length, value) = encoded.split_at_mut(8);
        length.copy_from_slice(&field_len.to_be_bytes());
        value.copy_from_slice(field);
        self.remaining = tail;
        Ok(())
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }
}
