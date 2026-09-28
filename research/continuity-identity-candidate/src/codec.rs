// SPDX-License-Identifier: Apache-2.0 OR MIT
use crate::Error;

pub(crate) struct Decoder<'a>(&'a [u8]);

impl<'a> Decoder<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }

    pub(crate) fn take(&mut self, length: usize) -> Result<&'a [u8], Error> {
        let value = self.0.get(..length).ok_or(Error::Encoding)?;
        self.0 = self.0.get(length..).ok_or(Error::Encoding)?;
        Ok(value)
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.take(N)?.try_into().map_err(|_| Error::Encoding)
    }

    pub(crate) fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    pub(crate) fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    pub(crate) fn finish(self) -> Result<(), Error> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(Error::Encoding)
        }
    }
}

pub(crate) fn nonzero<const N: usize>(value: &[u8; N]) -> Result<(), Error> {
    if value.iter().any(|byte| *byte != 0) {
        Ok(())
    } else {
        Err(Error::Encoding)
    }
}

pub(crate) fn generation(value: u64) -> Result<(), Error> {
    if value != 0 && value != u64::MAX {
        Ok(())
    } else {
        Err(Error::Encoding)
    }
}
