//! Merkle-Damgard padding without cloning the input.
//!
//! All three hashes (MD5, SHA-1, SHA-256) used to do `let mut msg =
//! data.to_vec()` before appending the 0x80/length suffix, which doubles
//! peak memory for every hashed buffer — `compare` of two 100 MB files
//! measured 303 MB RSS. These helpers process full 64-byte blocks straight
//! from the input slice and build only the final partial block (<= 128
//! bytes) in a local buffer.

/// Call `block` for every 64-byte chunk of the Merkle-Damgard stream:
/// all full blocks of `data`, then one padded tail block with the total
/// bit length appended (MD5: little-endian, SHA-1/SHA-256: big-endian).
pub fn for_each_block<F: FnMut(&[u8; 64])>(data: &[u8], bitlen_le: bool, mut block: F) {
    let full = data.len() / 64;
    for i in 0..full {
        let mut b = [0u8; 64];
        b.copy_from_slice(&data[i * 64..(i + 1) * 64]);
        block(&b);
    }
    // tail: 0x80, zeros, then the 8-byte length at bytes 56..64; if the tail
    // does not fit (>= 56 remaining bytes), an extra zero block is needed first
    let rem = &data[full * 64..];
    let mut tail = [0u8; 128];
    tail[..rem.len()].copy_from_slice(rem);
    tail[rem.len()] = 0x80;
    let bitlen = (data.len() as u64).wrapping_mul(8);
    let len_bytes = if bitlen_le {
        bitlen.to_le_bytes()
    } else {
        bitlen.to_be_bytes()
    };
    let tail_len = rem.len() + 1;
    if tail_len > 56 {
        // crosses into the second block: first block carries the data + 0x80
        let mut b = [0u8; 64];
        b[..64].copy_from_slice(&tail[..64]);
        block(&b);
        // second block: zeros with the length at bytes 56..64
        let mut b2 = [0u8; 64];
        b2[56..].copy_from_slice(&len_bytes);
        block(&b2);
        return;
    }
    tail[56..64].copy_from_slice(&len_bytes);
    let mut b = [0u8; 64];
    b.copy_from_slice(&tail[..64]);
    block(&b);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_cover_input_exactly() {
        // every length 0..=200: total block bytes consumed must equal
        // padded length, and full blocks must match the input prefix
        for n in 0..=200usize {
            let data: Vec<u8> = (0..n).map(|i| i as u8).collect();
            let mut count = 0;
            let mut first_bytes: Vec<u8> = Vec::new();
            for_each_block(&data, false, |b| {
                if count == 0 {
                    first_bytes.extend_from_slice(b);
                }
                assert_eq!(b.len(), 64);
                count += 1;
            });
            // expected padded block count
            let padded_len = if n % 64 < 56 {
                (n / 64 + 1) * 64
            } else {
                (n / 64 + 2) * 64
            };
            assert_eq!(count * 64, padded_len, "n={n}");
            // the first block's data prefix must match the input
            if n > 0 {
                let expect = &data[..n.min(64)];
                assert_eq!(&first_bytes[..expect.len()], expect, "n={n}");
            }
        }
    }
}
