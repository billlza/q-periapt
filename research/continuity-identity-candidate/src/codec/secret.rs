// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Length measurement and exact-capacity secret encoding share one serializer.
use crate::Error;
use zeroize::Zeroizing;

pub(crate) trait ByteWriter {
    fn extend_from_slice(&mut self, bytes: &[u8]);
    fn push(&mut self, value: u8) {
        self.extend_from_slice(&[value]);
    }
}
impl ByteWriter for Vec<u8> {
    fn extend_from_slice(&mut self, bytes: &[u8]) {
        Vec::extend_from_slice(self, bytes);
    }
}
impl ByteWriter for Zeroizing<Vec<u8>> {
    fn extend_from_slice(&mut self, bytes: &[u8]) {
        Vec::extend_from_slice(self, bytes);
    }
}

struct Length(Option<usize>);
impl ByteWriter for Length {
    fn extend_from_slice(&mut self, bytes: &[u8]) {
        self.0 = self.0.and_then(|size| size.checked_add(bytes.len()));
    }
}
pub(crate) fn encoded_len(
    encode: impl Fn(&mut dyn ByteWriter) -> Result<(), Error>,
) -> Result<usize, Error> {
    let mut count = Length(Some(0));
    encode(&mut count)?;
    count.0.ok_or(Error::Capacity)
}

struct Exact {
    bytes: Zeroizing<Vec<u8>>,
    length: usize,
    overflow: bool,
}
impl ByteWriter for Exact {
    fn extend_from_slice(&mut self, bytes: &[u8]) {
        if self
            .bytes
            .len()
            .checked_add(bytes.len())
            .is_some_and(|end| end <= self.length)
        {
            self.bytes.extend_from_slice(bytes);
        } else {
            // Record the encoding failure without releasing an unzeroized
            // allocation through Vec growth. encode_secret rejects the result.
            self.overflow = true;
        }
    }
}

pub(crate) fn encode_secret(
    encode: impl Fn(&mut dyn ByteWriter) -> Result<(), Error>,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let length = encoded_len(&encode)?;
    let mut out = Exact {
        bytes: Zeroizing::new(Vec::with_capacity(length)),
        length,
        overflow: false,
    };
    encode(&mut out)?;
    if out.overflow || out.bytes.len() != length {
        return Err(Error::Encoding);
    }
    Ok(out.bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn exact_writer_preserves_bytes_without_growing_the_secret_allocation() {
        let mut out = Exact {
            bytes: Zeroizing::new(Vec::with_capacity(64)),
            length: 64,
            overflow: false,
        };
        let address = out.bytes.as_ptr();
        out.extend_from_slice(&[0xa5; 32]);
        for _ in 0..32 {
            out.push(0x5a);
        }
        assert!(std::ptr::eq(out.bytes.as_ptr(), address));
        assert_eq!(
            out.bytes.as_slice(),
            [&[0xa5; 32][..], &[0x5a; 32][..]].concat()
        );
        assert!(!out.overflow);
        out.push(0xff);
        assert!(out.overflow);
        assert_eq!(out.bytes.len(), 64);
        assert!(std::ptr::eq(out.bytes.as_ptr(), address));
    }

    #[test]
    fn measured_and_written_lengths_must_match_in_both_directions() {
        for grow in [false, true] {
            let pass = Cell::new(0);
            let result = encode_secret(|out| {
                let first = pass.get() == 0;
                pass.set(pass.get() + 1);
                out.extend_from_slice(if first == grow { b"a" } else { b"ab" });
                Ok(())
            });
            assert!(matches!(result, Err(Error::Encoding)));
            assert_eq!(pass.get(), 2);
        }
    }

    #[test]
    fn errors_from_either_pass_are_returned() {
        for fail_at in [1, 2] {
            let pass = Cell::new(0);
            let result = encode_secret(|out| {
                pass.set(pass.get() + 1);
                out.extend_from_slice(b"private");
                if pass.get() == fail_at {
                    Err(Error::Provider)
                } else {
                    Ok(())
                }
            });
            assert!(matches!(result, Err(Error::Provider)));
            assert_eq!(pass.get(), fail_at);
        }
    }

    #[test]
    fn length_overflow_is_terminal_and_empty_encoding_is_valid() {
        let mut count = Length(Some(usize::MAX));
        count.push(1);
        count.extend_from_slice(&[]);
        assert!(count.0.is_none());
        let empty = encode_secret(|_| Ok(())).expect("empty encoding");
        assert!(empty.is_empty());
        let value = encode_secret(|out| {
            out.extend_from_slice(b"ab");
            out.push(b'c');
            Ok(())
        })
        .expect("encoding");
        assert_eq!(value.as_slice(), b"abc");
    }
}
