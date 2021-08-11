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
    let mut hash = vec![0u8; buf.len()];
    hasher.update_rayon(&iv);
    hasher.finalize_xof().fill(&mut hash);
    buf.par_iter_mut().zip(hash).for_each(|(b, h)| *b ^= h);
    if !d {
        hasher.reset();
        hasher.update_rayon(&buf);
        Ok([iv.to_vec(), buf, hasher.finalize().as_bytes().to_vec()].concat())
    } else {
        Ok(buf)
    }
}
