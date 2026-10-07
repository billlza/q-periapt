//! Allocation-free LP8 primitives shared by candidate canonical codecs.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CodecError {
    LengthOverflow,
    OutputTooShort,
    TruncatedLength,
    TruncatedValue,
}

pub(crate) struct LpWriter<'a> {
    remaining: &'a mut [u8],
}

impl<'a> LpWriter<'a> {
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

pub(crate) struct LpReader<'a> {
    remaining: &'a [u8],
}

impl<'a> LpReader<'a> {
    pub(crate) const fn new(encoded: &'a [u8]) -> Self {
        Self { remaining: encoded }
    }

    pub(crate) fn field(&mut self) -> Result<&'a [u8], CodecError> {
        let length_bytes = self.remaining.get(..8).ok_or(CodecError::TruncatedLength)?;
        let mut encoded_length = [0u8; 8];
        encoded_length.copy_from_slice(length_bytes);
        let field_len = usize::try_from(u64::from_be_bytes(encoded_length))
            .map_err(|_| CodecError::LengthOverflow)?;
        let needed = 8usize
            .checked_add(field_len)
            .ok_or(CodecError::LengthOverflow)?;
        let complete = self
            .remaining
            .get(..needed)
            .ok_or(CodecError::TruncatedValue)?;
        let (_, field) = complete.split_at(8);
        self.remaining = self
            .remaining
            .get(needed..)
            .ok_or(CodecError::TruncatedValue)?;
        Ok(field)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }
}
