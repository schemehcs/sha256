use chunk_buf::{Chunk, ChunkBuf};
use hasher_style::HasherStyle;
use std::ops::AddAssign;

pub const HASH_LEN: usize = 32;
pub const BLOCK_LEN: usize = 64;
pub type Hash = [u8; HASH_LEN];

static K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

#[derive(Clone)]
struct Vars {
    a: u32,
    b: u32,
    c: u32,
    d: u32,
    e: u32,
    f: u32,
    g: u32,
    h: u32,
}

impl Default for Vars {
    fn default() -> Self {
        Self {
            a: 0x6a09e667,
            b: 0xbb67ae85,
            c: 0x3c6ef372,
            d: 0xa54ff53a,
            e: 0x510e527f,
            f: 0x9b05688c,
            g: 0x1f83d9ab,
            h: 0x5be0cd19,
        }
    }
}

// clear memory footprint
impl Drop for Vars {
    fn drop(&mut self) {
        self.a = 0;
        self.b = 0;
        self.c = 0;
        self.d = 0;
        self.e = 0;
        self.f = 0;
        self.g = 0;
        self.h = 0;
    }
}

impl Vars {
    pub fn roll(&mut self, work: &[u32; 64]) {
        let mut t1: u32;
        let mut t2: u32;
        for i in 0..64 {
            t1 = self
                .h
                .wrapping_add(Self::bsig1(self.e))
                .wrapping_add(Self::ch(self.e, self.f, self.g))
                .wrapping_add(K[i])
                .wrapping_add(work[i]);
            t2 = Self::bsig0(self.a).wrapping_add(Self::maj(self.a, self.b, self.c));
            self.h = self.g;
            self.g = self.f;
            self.f = self.e;
            self.e = self.d.wrapping_add(t1);
            self.d = self.c;
            self.c = self.b;
            self.b = self.a;
            self.a = t1.wrapping_add(t2);
        }
    }

    pub fn update(&mut self, work: &[u32; 64]) {
        let mut cln = self.clone();
        cln.roll(work);
        self.add_assign(cln);
    }

    pub fn digest(&self) -> Hash {
        self.a
            .to_be_bytes()
            .into_iter()
            .chain(self.b.to_be_bytes())
            .chain(self.c.to_be_bytes())
            .chain(self.d.to_be_bytes())
            .chain(self.e.to_be_bytes())
            .chain(self.f.to_be_bytes())
            .chain(self.g.to_be_bytes())
            .chain(self.h.to_be_bytes())
            .collect::<Vec<u8>>()
            .try_into()
            .unwrap()
    }

    fn ch(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (!x & z)
    }

    fn maj(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (x & z) ^ (y & z)
    }

    fn bsig0(x: u32) -> u32 {
        x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
    }

    fn bsig1(x: u32) -> u32 {
        x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
    }
}

impl AddAssign for Vars {
    fn add_assign(&mut self, rhs: Self) {
        self.a = self.a.wrapping_add(rhs.a);
        self.b = self.b.wrapping_add(rhs.b);
        self.c = self.c.wrapping_add(rhs.c);
        self.d = self.d.wrapping_add(rhs.d);
        self.e = self.e.wrapping_add(rhs.e);
        self.f = self.f.wrapping_add(rhs.f);
        self.g = self.g.wrapping_add(rhs.g);
        self.h = self.h.wrapping_add(rhs.h);
    }
}

#[derive(Clone)]
struct State {
    vars: Vars,
    work: [u32; 64],
    cursor: usize,
}

impl Default for State {
    fn default() -> Self {
        State {
            vars: Vars::default(),
            work: [0; 64],
            cursor: 0,
        }
    }
}

// clear memory footprint
impl Drop for State {
    fn drop(&mut self) {
        self.work.fill(0);
    }
}

impl State {
    pub fn update(&mut self, n: u32) {
        self.work[self.cursor] = n;
        self.cursor += 1;
        if self.cursor < 16 {
            return;
        }
        self.expand();
        self.cursor = 0;
    }

    pub fn expand(&mut self) {
        for t in 16..64 {
            self.work[t] = Self::ssig1(self.work[t - 2])
                .wrapping_add(Self::ssig0(self.work[t - 15]))
                .wrapping_add(self.work[t - 7])
                .wrapping_add(self.work[t - 16]);
        }
        self.vars.update(&self.work);
    }

    pub fn finish(&mut self, n: u32, byte_len: usize) -> Hash {
        self.update(n);
        if self.cursor <= 14 {
            self.work[self.cursor..14].fill(0);
            self.fill_len(byte_len);
            self.expand();
        } else {
            self.work[self.cursor..16].fill(0);
            self.expand();
            self.work[..14].fill(0);
            self.fill_len(byte_len);
            self.expand();
        }
        self.vars.digest()
    }

    fn fill_len(&mut self, byte_len: usize) {
        let bit_len: u64 = (byte_len as u64) * 8;
        self.work[14] = (bit_len >> 32) as u32;
        self.work[15] = bit_len as u32;
    }

    fn ssig0(x: u32) -> u32 {
        x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
    }

    fn ssig1(x: u32) -> u32 {
        x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
    }
}

#[derive(Clone)]
pub struct Sha256 {
    state: State,
    buf: ChunkBuf<u8>,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self {
            state: State::default(),
            buf: ChunkBuf::new(4),
        }
    }
}

impl Sha256 {
    pub fn new() -> Self {
        Self::default()
    }
}

impl HasherStyle for Sha256 {
    type Output = Hash;

    fn write(&mut self, mut buf: &[u8]) -> &mut Self {
        while let Some(Chunk { bytes, consumed }) = self.buf.update(buf) {
            let n = u32::from_be_bytes(bytes.try_into().unwrap());
            self.state.update(n);
            buf = &buf[consumed..];
        }
        self
    }

    fn finish(&mut self) -> Self::Output {
        let n = match self.buf.update(&[0x80]) {
            Some(Chunk { bytes, .. }) => u32::from_be_bytes(bytes.try_into().unwrap()),
            None => {
                let mut last_u32 = [0u8; 4];
                let remainder = self.buf.remainder();
                last_u32[..remainder.len()].copy_from_slice(remainder);
                u32::from_be_bytes(last_u32)
            }
        };
        self.state.finish(n, self.buf.acc_consumed() - 1)
    }
}

#[inline]
pub fn digest(msg: &[u8]) -> Hash {
    Sha256::new().write(msg).finish()
}

#[deprecated]
pub fn sha256(msg: &[u8]) -> Hash {
    Sha256::new().write(msg).finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn len0_string() {
        let empty: [u8; 0] = [];
        let digest = digest(&empty);
        let expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(expected, hex::encode(digest));
    }

    #[test]
    fn len1_string() {
        let msg = "H".as_bytes();
        let expected = "44bd7ae60f478fae1061e11a7739f4b94d1daf917982d33b6fc8a01a63f89c21";
        let digest = digest(msg);
        assert_eq!(expected, hex::encode(digest));
    }

    #[test]
    fn len511_string() {
        let msg = "315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3\
                        315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3\
                        315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3\
                        315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3\
                        315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3\
                        315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3\
                        315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3\
                        315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd"
            .as_bytes();
        let expected = "fc1c3103cc791e104373c82520c42cb5266850c8d0504da922b982abe9cc6452";
        let digest = digest(msg);
        assert_eq!(expected, hex::encode(digest));
    }

    #[test]
    fn len512_string() {
        let msg = "315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3\
                        315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3\
                        315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3\
                        315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3\
                        315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3\
                        315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3\
                        315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3\
                        315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3"
            .as_bytes();
        let expected = "0b221c1e7ae3b092e85829eecbe51205947044701dfa05b7c6f0759b207cebea";
        let digest = digest(msg);
        assert_eq!(expected, hex::encode(digest));
    }

    #[test]
    fn len513_string() {
        let msg = "315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3\
                        315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3\
                        315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3\
                        315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3\
                        315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3\
                        315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3\
                        315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3\
                        315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3\
                        3"
        .as_bytes();
        let expected = "e39db0e4cc4d81ff74f04dda25d5e2ca3866776d2396fa6e73df1e94d2c14b70";
        let digest = digest(msg);
        assert_eq!(expected, hex::encode(digest));
    }
}
