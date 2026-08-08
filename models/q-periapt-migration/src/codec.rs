//! Private fixed-width LP8 writer for the migration-context body.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CodecError {
    LengthOverflow,
    OutputTooShort,
    TruncatedLength,
    TruncatedValue,
    TrailingBytes,
}

pub(crate) struct Lp8Writer<'a> {
    remaining: &'a mut [u8],
}

pub(crate) struct Lp8Reader<'a> {
    remaining: &'a [u8],
}

impl<'a> Lp8Reader<'a> {
    pub(crate) const fn new(encoded: &'a [u8]) -> Self {
        Self { remaining: encoded }
    }

    pub(crate) fn field(&mut self) -> Result<&'a [u8], CodecError> {
        let length = self.remaining.get(..8).ok_or(CodecError::TruncatedLength)?;
        let mut encoded_length = [0u8; 8];
        encoded_length.copy_from_slice(length);
        let field_len = usize::try_from(u64::from_be_bytes(encoded_length))
            .map_err(|_| CodecError::LengthOverflow)?;
        let end = 8usize
            .checked_add(field_len)
            .ok_or(CodecError::LengthOverflow)?;
        let complete = self
            .remaining
            .get(..end)
            .ok_or(CodecError::TruncatedValue)?;
        let field = complete.get(8..).ok_or(CodecError::TruncatedValue)?;
        self.remaining = self
            .remaining
            .get(end..)
            .ok_or(CodecError::TruncatedValue)?;
        Ok(field)
    }

    pub(crate) fn finish(self) -> Result<(), CodecError> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(CodecError::TrailingBytes)
        }
    }
}

pub(crate) fn encoded_lp8_len(fields: &[&[u8]]) -> Result<usize, CodecError> {
    fields.iter().try_fold(0usize, |total, field| {
        total
            .checked_add(8)
            .and_then(|value| value.checked_add(field.len()))
            .ok_or(CodecError::LengthOverflow)
    })
}

pub(crate) fn encode_lp8_fields(fields: &[&[u8]]) -> Result<Vec<u8>, CodecError> {
    let len = encoded_lp8_len(fields)?;
    let mut encoded = vec![0u8; len];
    let mut writer = Lp8Writer::new(&mut encoded);
    for field in fields {
        writer.field(field)?;
    }
    if !writer.is_empty() {
        return Err(CodecError::OutputTooShort);
    }
    Ok(encoded)
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
