// Copyright 2026 KDFT contributors
// SPDX-License-Identifier: Apache-2.0

//! Strict, allocation-bounded LZNT1 decompression for NTFS compression units.
//!
//! LZNT1 divides its output into independently encoded chunks of at most 4096
//! bytes.  Each chunk starts with a little-endian 16-bit header.  A zero header
//! terminates the stream; otherwise bits 14..=12 must contain the signature 3,
//! bit 15 selects compressed or literal data, and bits 11..=0 encode the total
//! chunk size minus three.
//!
//! [`decompress_lznt1`] requires the logical output length.  This is important
//! for NTFS because the last physical cluster of a compressed unit can contain
//! zero padding, while the last logical unit of a stream can be shorter than a
//! complete compression unit.  The function returns exactly the requested
//! number of bytes or an error; it never silently returns partial data.

use std::error::Error;
use std::fmt;

/// Maximum uncompressed size of one LZNT1 chunk.
pub const LZNT1_CHUNK_SIZE: usize = 4096;

const CHUNK_SIGNATURE_MASK: u16 = 0x7000;
const CHUNK_SIGNATURE: u16 = 0x3000;
const CHUNK_COMPRESSED: u16 = 0x8000;
const CHUNK_SIZE_MASK: u16 = 0x0fff;

/// A structural or bounds error encountered while decoding LZNT1 data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Lznt1Error {
    /// Fewer bytes remained than were required to read the next structure.
    TruncatedInput {
        offset: usize,
        needed: usize,
        remaining: usize,
        context: &'static str,
    },
    /// Bits 14..=12 of a non-terminal chunk header were not the required value 3.
    InvalidChunkSignature { offset: usize, header: u16 },
    /// A chunk header declared more bytes than remain in the supplied input.
    ChunkOutsideInput {
        offset: usize,
        declared_size: usize,
        remaining: usize,
    },
    /// A match attempted to refer to bytes before the beginning of its chunk.
    InvalidBackReference {
        offset: usize,
        displacement: usize,
        produced_in_chunk: usize,
    },
    /// Decoding a compressed chunk would have produced more than 4096 bytes.
    ChunkOutputTooLarge {
        offset: usize,
        attempted_size: usize,
    },
    /// Decoding stopped before the caller's trusted logical length was reached.
    OutputLengthMismatch { expected: usize, actual: usize },
    /// Nonzero bytes followed the complete logical output or an end marker.
    NonzeroTrailingData { offset: usize },
}

impl fmt::Display for Lznt1Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedInput {
                offset,
                needed,
                remaining,
                context,
            } => write!(
                f,
                "truncated LZNT1 {context} at input offset {offset}: needed {needed} byte(s), only {remaining} remain"
            ),
            Self::InvalidChunkSignature { offset, header } => write!(
                f,
                "invalid LZNT1 chunk signature at input offset {offset}: header 0x{header:04x}"
            ),
            Self::ChunkOutsideInput {
                offset,
                declared_size,
                remaining,
            } => write!(
                f,
                "LZNT1 chunk at input offset {offset} declares {declared_size} byte(s), only {remaining} remain"
            ),
            Self::InvalidBackReference {
                offset,
                displacement,
                produced_in_chunk,
            } => write!(
                f,
                "invalid LZNT1 back-reference at input offset {offset}: displacement {displacement} exceeds {produced_in_chunk} byte(s) produced in this chunk"
            ),
            Self::ChunkOutputTooLarge {
                offset,
                attempted_size,
            } => write!(
                f,
                "LZNT1 chunk at input offset {offset} would expand to {attempted_size} bytes (maximum {LZNT1_CHUNK_SIZE})"
            ),
            Self::OutputLengthMismatch { expected, actual } => write!(
                f,
                "LZNT1 output length mismatch: expected {expected} byte(s), decoded {actual}"
            ),
            Self::NonzeroTrailingData { offset } => write!(
                f,
                "nonzero data follows complete LZNT1 output at input offset {offset}"
            ),
        }
    }
}

impl Error for Lznt1Error {}

/// Decompress an LZNT1 buffer to exactly `expected_length` logical bytes.
///
/// The decoder accepts an optional zero end marker and zero-filled physical
/// padding after the encoded chunks.  Any nonzero trailing byte is rejected so
/// that a caller cannot accidentally decode only a prefix of a physical run.
/// The final decoded chunk is trimmed only when `expected_length` ends inside
/// that chunk, which is how NTFS represents a short final compression unit.
pub fn decompress_lznt1(input: &[u8], expected_length: usize) -> Result<Vec<u8>, Lznt1Error> {
    let mut input_offset = 0usize;
    let mut output = Vec::new();

    while output.len() < expected_length {
        let remaining = input.len().saturating_sub(input_offset);
        if remaining < 2 {
            return Err(Lznt1Error::TruncatedInput {
                offset: input_offset,
                needed: 2,
                remaining,
                context: "chunk header",
            });
        }

        let header = u16::from_le_bytes([input[input_offset], input[input_offset + 1]]);
        if header == 0 {
            input_offset += 2;
            ensure_zero_tail(input, input_offset)?;
            return Err(Lznt1Error::OutputLengthMismatch {
                expected: expected_length,
                actual: output.len(),
            });
        }

        if header & CHUNK_SIGNATURE_MASK != CHUNK_SIGNATURE {
            return Err(Lznt1Error::InvalidChunkSignature {
                offset: input_offset,
                header,
            });
        }

        // Bits 11..=0 store the total chunk size minus three.  The total
        // therefore includes this two-byte header and contains at least one
        // payload byte.
        let chunk_size = usize::from(header & CHUNK_SIZE_MASK) + 3;
        if chunk_size > remaining {
            return Err(Lznt1Error::ChunkOutsideInput {
                offset: input_offset,
                declared_size: chunk_size,
                remaining,
            });
        }

        let payload_start = input_offset + 2;
        let payload_end = input_offset + chunk_size;
        let payload = &input[payload_start..payload_end];
        let decoded = if header & CHUNK_COMPRESSED == 0 {
            payload.to_vec()
        } else {
            decompress_chunk(payload, payload_start)?
        };

        let logical_remaining = expected_length - output.len();
        let bytes_to_take = decoded.len().min(logical_remaining);
        output.extend_from_slice(&decoded[..bytes_to_take]);
        input_offset = payload_end;
    }

    ensure_zero_tail(input, input_offset)?;
    Ok(output)
}

fn decompress_chunk(payload: &[u8], payload_input_offset: usize) -> Result<Vec<u8>, Lznt1Error> {
    let mut cursor = 0usize;
    let mut output = Vec::new();

    while cursor < payload.len() {
        let flag_offset = payload_input_offset + cursor;
        let flags = payload[cursor];
        cursor += 1;
        let mut tokens_in_group = 0usize;

        for token_index in 0..8 {
            // A final flag group may contain fewer than eight tokens, but it
            // must contain at least one token.
            if cursor == payload.len() {
                if tokens_in_group == 0 {
                    return Err(Lznt1Error::TruncatedInput {
                        offset: flag_offset + 1,
                        needed: 1,
                        remaining: 0,
                        context: "flag-group token",
                    });
                }
                break;
            }

            let is_match = flags & (1 << token_index) != 0;
            if !is_match {
                output.push(payload[cursor]);
                cursor += 1;
                tokens_in_group += 1;
                if output.len() > LZNT1_CHUNK_SIZE {
                    return Err(Lznt1Error::ChunkOutputTooLarge {
                        offset: flag_offset,
                        attempted_size: output.len(),
                    });
                }
                continue;
            }

            let token_offset = payload_input_offset + cursor;
            let remaining = payload.len() - cursor;
            if remaining < 2 {
                return Err(Lznt1Error::TruncatedInput {
                    offset: token_offset,
                    needed: 2,
                    remaining,
                    context: "back-reference token",
                });
            }

            let token = u16::from_le_bytes([payload[cursor], payload[cursor + 1]]);
            cursor += 2;
            tokens_in_group += 1;

            let (length_mask, displacement_shift) = token_layout(output.len());
            let length = usize::from(token & length_mask) + 3;
            let displacement = usize::from(token >> displacement_shift) + 1;
            if displacement > output.len() {
                return Err(Lznt1Error::InvalidBackReference {
                    offset: token_offset,
                    displacement,
                    produced_in_chunk: output.len(),
                });
            }

            let attempted_size = output.len().saturating_add(length);
            if attempted_size > LZNT1_CHUNK_SIZE {
                return Err(Lznt1Error::ChunkOutputTooLarge {
                    offset: token_offset,
                    attempted_size,
                });
            }

            // Copy byte-by-byte: LZNT1 explicitly permits a match length larger
            // than its displacement, so newly emitted bytes can be the source
            // of later bytes in the same match.
            for _ in 0..length {
                let source = output.len() - displacement;
                let byte = output[source];
                output.push(byte);
            }
        }
    }

    Ok(output)
}

fn token_layout(produced_in_chunk: usize) -> (u16, u32) {
    let mut length_mask = 0x0fffu16;
    let mut displacement_shift = 12u32;
    // MS-XCA derives the dynamic split from the zero-based index of the
    // previously emitted byte, not from the next output offset.  Using
    // `produced_in_chunk` directly changes the layout one token too early at
    // exact powers of two (16, 32, 64, ...), turning valid lengths into
    // impossible back-reference displacements.
    let mut position = produced_in_chunk.saturating_sub(1);

    while position >= 0x10 {
        length_mask >>= 1;
        displacement_shift -= 1;
        position >>= 1;
    }

    (length_mask, displacement_shift)
}

fn ensure_zero_tail(input: &[u8], offset: usize) -> Result<(), Lznt1Error> {
    if let Some(relative) = input[offset..].iter().position(|byte| *byte != 0) {
        return Err(Lznt1Error::NonzeroTrailingData {
            offset: offset + relative,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use sha2::{Digest, Sha256};
    use std::{env, path::PathBuf};

    fn chunk_header(compressed: bool, payload_len: usize) -> [u8; 2] {
        assert!((1..=LZNT1_CHUNK_SIZE).contains(&payload_len));
        let mut header = CHUNK_SIGNATURE | u16::try_from(payload_len - 1).unwrap();
        if compressed {
            header |= CHUNK_COMPRESSED;
        }
        header.to_le_bytes()
    }

    #[test]
    fn decompresses_uncompressed_four_kib_chunk() {
        let expected: Vec<u8> = (0..LZNT1_CHUNK_SIZE)
            .map(|index| ((index * 29 + 7) & 0xff) as u8)
            .collect();
        let mut encoded = Vec::from(chunk_header(false, expected.len()));
        encoded.extend_from_slice(&expected);

        assert_eq!(
            decompress_lznt1(&encoded, expected.len()).unwrap(),
            expected
        );
    }

    #[test]
    fn decompresses_compressed_four_kib_chunk_with_overlap() {
        // Literal 'A', followed by a displacement-1 match of length 4095.
        // At output position 1 the token layout is 4 displacement bits and 12
        // length bits, so (4095 - 3) is encoded as 0x0ffc.
        let encoded = [0x03, 0xb0, 0x02, b'A', 0xfc, 0x0f];
        let decoded = decompress_lznt1(&encoded, LZNT1_CHUNK_SIZE).unwrap();

        assert_eq!(decoded.len(), LZNT1_CHUNK_SIZE);
        assert!(decoded.iter().all(|byte| *byte == b'A'));
    }

    #[test]
    fn decodes_microsoft_lznt1_example() {
        // [MS-XCA] section 3.3, including the terminal NUL.
        let encoded = [
            0x38, 0xb0, 0x88, 0x46, 0x23, 0x20, 0x00, 0x20, 0x47, 0x20, 0x41, 0x00, 0x10, 0xa2,
            0x47, 0x01, 0xa0, 0x45, 0x20, 0x44, 0x00, 0x08, 0x45, 0x01, 0x50, 0x79, 0x00, 0xc0,
            0x45, 0x20, 0x05, 0x24, 0x13, 0x88, 0x05, 0xb4, 0x02, 0x4a, 0x44, 0xef, 0x03, 0x58,
            0x02, 0x8c, 0x09, 0x16, 0x01, 0x48, 0x45, 0x00, 0xbe, 0x00, 0x9e, 0x00, 0x04, 0x01,
            0x18, 0x90, 0x00,
        ];
        let expected = b"F# F# G A A G F# E D D E F# F# E E F# F# G A A G F# E D D E F# E D D E E F# D E F# G F# D E F# G F# E D E A F# F# G A A G F# E D D E F# E D D\0";

        assert_eq!(
            decompress_lznt1(&encoded, expected.len()).unwrap(),
            expected
        );
    }

    #[test]
    fn concatenates_independent_chunks() {
        let first = [0x03, 0xb0, 0x02, b'A', 0xfc, 0x0f];
        let mut encoded = first.to_vec();
        encoded.extend_from_slice(&chunk_header(false, LZNT1_CHUNK_SIZE));
        encoded.extend(std::iter::repeat_n(b'B', LZNT1_CHUNK_SIZE));

        let decoded = decompress_lznt1(&encoded, LZNT1_CHUNK_SIZE * 2).unwrap();
        assert_eq!(&decoded[..LZNT1_CHUNK_SIZE], &[b'A'; LZNT1_CHUNK_SIZE]);
        assert_eq!(&decoded[LZNT1_CHUNK_SIZE..], &[b'B'; LZNT1_CHUNK_SIZE]);
    }

    #[test]
    fn trims_literal_padding_to_expected_length() {
        let mut encoded = Vec::from(chunk_header(false, LZNT1_CHUNK_SIZE));
        encoded.extend_from_slice(b"EVTX");
        encoded.resize(2 + LZNT1_CHUNK_SIZE, 0);

        assert_eq!(decompress_lznt1(&encoded, 4).unwrap(), b"EVTX");
    }

    #[test]
    fn accepts_end_marker_and_zero_physical_padding() {
        let mut encoded = Vec::from(chunk_header(false, 3));
        encoded.extend_from_slice(b"abc");
        encoded.extend_from_slice(&[0, 0]);
        encoded.resize(512, 0);

        assert_eq!(decompress_lznt1(&encoded, 3).unwrap(), b"abc");
        assert_eq!(decompress_lznt1(&[0; 32], 0).unwrap(), b"");
    }

    #[test]
    fn rejects_short_output_instead_of_returning_partial_data() {
        let mut encoded = Vec::from(chunk_header(false, 3));
        encoded.extend_from_slice(b"abc");

        assert_eq!(
            decompress_lznt1(&encoded, 4),
            Err(Lznt1Error::TruncatedInput {
                offset: 5,
                needed: 2,
                remaining: 0,
                context: "chunk header",
            })
        );

        let mut terminated = encoded;
        terminated.extend_from_slice(&[0, 0]);
        assert_eq!(
            decompress_lznt1(&terminated, 4),
            Err(Lznt1Error::OutputLengthMismatch {
                expected: 4,
                actual: 3,
            })
        );
    }

    #[test]
    fn rejects_nonzero_data_after_expected_output() {
        let mut encoded = Vec::from(chunk_header(false, 3));
        encoded.extend_from_slice(b"abc");
        encoded.extend_from_slice(&[0, 0, 0x7f]);

        assert_eq!(
            decompress_lznt1(&encoded, 3),
            Err(Lznt1Error::NonzeroTrailingData { offset: 7 })
        );
    }

    #[test]
    fn rejects_truncated_header_and_declared_chunk() {
        assert_eq!(
            decompress_lznt1(&[0x03], 1),
            Err(Lznt1Error::TruncatedInput {
                offset: 0,
                needed: 2,
                remaining: 1,
                context: "chunk header",
            })
        );
        assert_eq!(
            decompress_lznt1(&[0xff, 0x3f, b'a'], 1),
            Err(Lznt1Error::ChunkOutsideInput {
                offset: 0,
                declared_size: 4098,
                remaining: 3,
            })
        );
    }

    #[test]
    fn rejects_invalid_chunk_signature() {
        assert_eq!(
            decompress_lznt1(&[0x00, 0x20, b'x'], 1),
            Err(Lznt1Error::InvalidChunkSignature {
                offset: 0,
                header: 0x2000,
            })
        );
    }

    #[test]
    fn rejects_flag_group_without_a_token() {
        // Total chunk size 3: two-byte header and only a flag byte.
        assert_eq!(
            decompress_lznt1(&[0x00, 0xb0, 0x00], 1),
            Err(Lznt1Error::TruncatedInput {
                offset: 3,
                needed: 1,
                remaining: 0,
                context: "flag-group token",
            })
        );
    }

    #[test]
    fn rejects_truncated_back_reference() {
        // Flag bit 0 says match, but only one byte of the two-byte token exists.
        assert_eq!(
            decompress_lznt1(&[0x01, 0xb0, 0x01, 0x00], 3),
            Err(Lznt1Error::TruncatedInput {
                offset: 3,
                needed: 2,
                remaining: 1,
                context: "back-reference token",
            })
        );
    }

    #[test]
    fn rejects_back_reference_before_chunk_start() {
        // The first token is a displacement-1 match, but no byte has been
        // produced in this independently decoded chunk.
        assert_eq!(
            decompress_lznt1(&[0x02, 0xb0, 0x01, 0x00, 0x00], 3),
            Err(Lznt1Error::InvalidBackReference {
                offset: 3,
                displacement: 1,
                produced_in_chunk: 0,
            })
        );
    }

    #[test]
    fn back_reference_cannot_cross_chunk_boundary() {
        let mut encoded = Vec::from(chunk_header(false, 1));
        encoded.push(b'A');
        encoded.extend_from_slice(&[0x02, 0xb0, 0x01, 0x00, 0x00]);

        assert_eq!(
            decompress_lznt1(&encoded, 4),
            Err(Lznt1Error::InvalidBackReference {
                offset: 6,
                displacement: 1,
                produced_in_chunk: 0,
            })
        );
    }

    #[test]
    fn rejects_chunk_expansion_past_four_kib() {
        // Literal 'A' plus a displacement-1 match of length 4096.
        assert_eq!(
            decompress_lznt1(&[0x03, 0xb0, 0x02, b'A', 0xfd, 0x0f], 4096),
            Err(Lznt1Error::ChunkOutputTooLarge {
                offset: 4,
                attempted_size: 4097,
            })
        );
    }

    #[test]
    fn token_layout_changes_after_not_at_power_of_two_boundaries() {
        assert_eq!(token_layout(15), (0x0fff, 12));
        assert_eq!(token_layout(16), (0x0fff, 12));
        assert_eq!(token_layout(17), (0x07ff, 11));
        assert_eq!(token_layout(128), (0x01ff, 9));
        assert_eq!(token_layout(129), (0x00ff, 8));
    }

    #[test]
    fn decodes_back_reference_at_exact_128_byte_boundary() {
        let mut payload = Vec::new();
        for group in 0..16_u8 {
            payload.push(0);
            payload.extend((0..8_u8).map(|index| group.wrapping_mul(8).wrapping_add(index)));
        }
        // At exactly 128 emitted bytes the layout remains a 9-bit
        // displacement/9-bit-length split.  This token means displacement 78,
        // length 3.  The historical gold EVTX exercises this boundary.
        payload.push(0x01);
        payload.extend_from_slice(&0x9a00_u16.to_le_bytes());

        let mut encoded = Vec::from(chunk_header(true, payload.len()));
        encoded.extend_from_slice(&payload);
        let decoded = decompress_lznt1(&encoded, 131).unwrap();
        assert_eq!(decoded.len(), 131);
        assert_eq!(&decoded[128..], &decoded[50..53]);
    }

    /// Read-only regression against the known LZNT1-compressed EVTX in the
    /// gold acquisition.  The test is deliberately ignored because the case
    /// database and segmented E01 are examiner-owned fixtures rather than
    /// repository test data.
    ///
    /// Run with:
    ///
    /// ```text
    /// KDFT_GOLD_CASE_PATH=<case.kdft.sqlite> cargo test -p kdft-case \
    ///     gold_ntfs_lznt1_evtx_entry_is_reconstructed -- --ignored --nocapture
    /// ```
    ///
    /// `KDFT_GOLD_NTFS_COMPRESSED_ENTRY_ID` may override the historical entry
    /// id (189561).  The query-only session prevents schema migration, WAL
    /// changes, audit events, or any other case mutation during validation.
    #[test]
    #[ignore = "requires the examiner-owned gold case database and segmented E01"]
    fn gold_ntfs_lznt1_evtx_entry_is_reconstructed() {
        let case_path = env::var_os("KDFT_GOLD_CASE_PATH")
            .map(PathBuf::from)
            .expect("KDFT_GOLD_CASE_PATH must name the historical indexed gold case");
        let entry_id = env::var("KDFT_GOLD_NTFS_COMPRESSED_ENTRY_ID")
            .ok()
            .map(|value| {
                value
                    .parse::<i64>()
                    .expect("KDFT_GOLD_NTFS_COMPRESSED_ENTRY_ID must be an i64")
            })
            .unwrap_or(189_561);

        let mut session = crate::EvidenceReadSession::open_worker_read_only(&case_path)
            .expect("open gold case query-only");
        let mut bytes = Vec::new();
        let mut total_size = None;
        let mut offset = 0_u64;

        loop {
            let read = crate::read_filesystem_entry_bytes_in_session(
                &mut session,
                crate::ReadEntryBytesOptions {
                    entry_id,
                    offset,
                    length: 1024 * 1024,
                },
            )
            .unwrap_or_else(|error| {
                panic!("reconstruct gold NTFS-compressed entry {entry_id} at {offset}: {error:#}")
            });
            let expected_total = *total_size.get_or_insert(read.total_size);
            assert_eq!(read.total_size, expected_total);
            assert_eq!(read.offset, offset);
            assert_eq!(read.bytes_read, read.bytes.len());
            assert!(
                read.total_size <= 256 * 1024 * 1024,
                "gold EVTX unexpectedly exceeds the bounded regression-test allocation"
            );
            assert!(
                !read.bytes.is_empty() || read.eof,
                "non-EOF gold entry read made no progress at offset {offset}"
            );
            bytes.extend_from_slice(&read.bytes);
            offset = offset
                .checked_add(read.bytes_read as u64)
                .expect("gold EVTX offset overflow");
            if read.eof {
                break;
            }
        }

        let total_size = total_size.expect("gold EVTX produced no read result");
        assert_eq!(offset, total_size);
        assert_eq!(bytes.len() as u64, total_size);
        assert_eq!(
            bytes.get(..8),
            Some(b"ElfFile\0".as_slice()),
            "reconstructed entry does not have an EVTX file signature"
        );
        if bytes.len() > 4096 {
            assert_eq!(
                bytes.get(4096..4104),
                Some(b"ElfChnk\0".as_slice()),
                "reconstructed EVTX does not have a first chunk signature"
            );
        }

        let sha256 = format!("{:x}", Sha256::digest(&bytes));

        let mut parser = evtx::EvtxParser::from_buffer(bytes)
            .expect("open reconstructed gold EVTX with the independent EVTX parser");
        let mut valid_records = 0_usize;
        let mut parse_errors = 0_usize;
        for record in parser.records() {
            match record {
                Ok(_) => valid_records += 1,
                Err(error) => {
                    parse_errors += 1;
                    eprintln!("gold EVTX record diagnostic: {error:#}");
                }
            }
        }
        assert_eq!(
            parse_errors, 0,
            "reconstructed gold EVTX produced independent parser diagnostics"
        );
        eprintln!(
            "validated compressed NTFS entry {entry_id}: {total_size} bytes, \
             SHA-256 {sha256}, {valid_records} EVTX record(s), \
             {parse_errors} parser diagnostic(s)"
        );
    }
}
