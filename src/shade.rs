use blake3;
use rand::{thread_rng, Rng};
use rayon::prelude::*;
use std::convert::TryInto;

#[inline(always)]
pub fn crypt_message(k: [u8; 32], p: Vec<u8>, d: bool) -> Result<Vec<u8>, &'static str> {
    let mut hasher = blake3::Hasher::new_keyed(&k);
    let mut iv = [0u8; 32];
    let mut buf: Vec<u8>;
    if d {
        iv = p[0..32].try_into().unwrap();
        buf = p[32..p.len() - 32].to_vec();
        hasher.update_rayon(&buf);
        if p[p.len() - 32..] != *hasher.finalize().as_bytes() {
            return Err("MAC Verification Failure");
        }
        hasher.reset();
    } else {
        thread_rng().fill(&mut iv);
        buf = p;
    }
    let mut hash = vec![0u8; 1 + ((buf.len() - 1) | 31)];
    hash.par_chunks_exact_mut(32)
        .enumerate()
        .for_each(|(i, q)| hash_block(q, iv, k, i));
    hash.par_chunks_exact_mut(32)
        .enumerate()
        .for_each(|(i, q)| hash_block(q, (*q).try_into().unwrap(), k, i));
    // hasher.update(&buf).finalize_xof().fill(&mut hash);
    hash.truncate(buf.len());
    buf.par_iter_mut().zip(hash).for_each(|(b, h)| *b ^= h);
    if !d {
        // let mac = buf
        //     .par_chunks_exact(32)
        //     .map(|v| hash_slice(v, k))
        //     .reduce_with(|a, b| {
        //         let mut c = a;
        //         for i in 0..32 {
        //             c[i] ^= b[i];
        //         }
        //         a
        //     })
        //     .unwrap();
        hasher.reset();
        hasher.update_rayon(&buf);
        Ok([iv.to_vec(), buf, hasher.finalize().as_bytes().to_vec()].concat())
        // Ok([iv.to_vec(), buf, mac.to_vec()].concat())
    } else {
        Ok(buf)
    }
}

#[inline(always)]
fn hash_block(q: &mut [u8], iv: [u8; 32], k: [u8; 32], bid: usize) {
    let mut buf = iv;
    for i in 0..32 {
        if i % 4 == 0 {
            buf[i] ^= ((bid >> (i * 2)) & 0xff) as u8;
        }
        buf[i] ^= k[i];
    }
    buf[..].rotate_right(1);
    for i in 0..32 {
        q[i] = buf[i].wrapping_add(iv[i]);
    }
}

// fn hash_slice(iv: [u8; 32], k: [u8; 32]) -> [u8; 32] {
//     let mut i = [0u8; 32];
//     hash_block(&mut i, iv, k, 0);
//     i
// }
