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

pub fn sha256(msg: &[u8]) -> [u8; 32] {
    let msg_bit_len = (msg.len() as u64) * 8;
    let mut hs: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut w = [0u32; 64];
    let mut chunks = msg.chunks_exact(64);
    for chunk in chunks.by_ref() {
        sha256_block(chunk.try_into().unwrap(), &mut hs, &mut w);
    }
    let mut padded: [u8; 64] = [0u8; 64];
    let rem = chunks.remainder();
    let cursor = rem.len();
    padded[..cursor].copy_from_slice(rem);
    if cursor < 56 {
        padded[rem.len()] = 0x80;
        padded[56..64].copy_from_slice(&msg_bit_len.to_be_bytes());
        sha256_block(&padded, &mut hs, &mut w);
    } else {
        padded[cursor] = 0x80;
        sha256_block(&padded, &mut hs, &mut w);
        padded[0..56].fill(0);
        padded[56..64].copy_from_slice(&msg_bit_len.to_be_bytes());
        sha256_block(&padded, &mut hs, &mut w);
    }
    let mut ret = [0_u8; 32];
    for i in (0..32).step_by(4) {
        ret[i..i + 4].copy_from_slice(&hs[i / 4].to_be_bytes());
    }
    ret
}

pub fn sha256_block(block: &[u8; 64], hs: &mut [u32; 8], w: &mut [u32; 64]) {
    prepare_message_schedule(block, w);
    let mut a = hs[0];
    let mut b = hs[1];
    let mut c = hs[2];
    let mut d = hs[3];
    let mut e = hs[4];
    let mut f = hs[5];
    let mut g = hs[6];
    let mut h = hs[7];

    let mut t1: u32;
    let mut t2: u32;
    for i in 0..64 {
        t1 = h
            .wrapping_add(bsig1(e))
            .wrapping_add(ch(e, f, g))
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        t2 = bsig0(a).wrapping_add(maj(a, b, c));
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    hs[0] = a.wrapping_add(hs[0]);
    hs[1] = b.wrapping_add(hs[1]);
    hs[2] = c.wrapping_add(hs[2]);
    hs[3] = d.wrapping_add(hs[3]);
    hs[4] = e.wrapping_add(hs[4]);
    hs[5] = f.wrapping_add(hs[5]);
    hs[6] = g.wrapping_add(hs[6]);
    hs[7] = h.wrapping_add(hs[7]);
}

fn prepare_message_schedule(block: &[u8; 64], w: &mut [u32; 64]) {
    for (i, chunk) in block.chunks(4).enumerate() {
        w[i] = u32::from_be_bytes(chunk.try_into().unwrap());
    }
    for i in 16..64 {
        w[i] = ssig1(w[i - 2])
            .wrapping_add(ssig0(w[i - 15]))
            .wrapping_add(w[i - 7])
            .wrapping_add(w[i - 16]);
    }
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

fn ssig0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}

fn ssig1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn len0_string() {
        let empty: [u8; 0] = [];
        let digest = sha256(&empty);
        let expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(expected, hex::encode(digest));
    }

    #[test]
    fn len1_string() {
        let msg = "H".as_bytes();
        let expected = "44bd7ae60f478fae1061e11a7739f4b94d1daf917982d33b6fc8a01a63f89c21";
        let digest = sha256(msg);
        assert_eq!(expected, hex::encode(digest));
    }

    #[test]
    fn len511_string() {
        let msg = "315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94\
                        c75894edd3315f5bdb76d078c43b8ac0064e4a0164612b1fce77c8693\
                        45bfc94c75894edd3315f5bdb76d078c43b8ac0064e4a0164612b1fce\
                        77c869345bfc94c75894edd3315f5bdb76d078c43b8ac0064e4a016461\
                        2b1fce77c869345bfc94c75894edd3315f5bdb76d078c43b8ac0064e4a\
                        0164612b1fce77c869345bfc94c75894edd3315f5bdb76d078c43b8ac0\
                        064e4a0164612b1fce77c869345bfc94c75894edd3315f5bdb76d078c4\
                        3b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3315f5bdb76\
                        d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd"
            .as_bytes();
        let expected = "fc1c3103cc791e104373c82520c42cb5266850c8d0504da922b982abe9cc6452";
        let digest = sha256(msg);
        assert_eq!(expected, hex::encode(digest));
    }

    #[test]
    fn len512_string() {
        let msg = "315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c\
        75894edd3315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd33\
        15f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3315f5bdb76d\
        078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3315f5bdb76d078c43b8ac\
        0064e4a0164612b1fce77c869345bfc94c75894edd3315f5bdb76d078c43b8ac0064e4a0164\
        612b1fce77c869345bfc94c75894edd3315f5bdb76d078c43b8ac0064e4a0164612b1fce77c\
        869345bfc94c75894edd3315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3"
            .as_bytes();
        let expected = "0b221c1e7ae3b092e85829eecbe51205947044701dfa05b7c6f0759b207cebea";
        let digest = sha256(msg);
        assert_eq!(expected, hex::encode(digest));
    }

    #[test]
    fn len513_string() {
        let msg = "315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc9\
                        4c75894edd3315f5bdb76d078c43b8ac0064e4a0164612b1fce77c86\
                        9345bfc94c75894edd3315f5bdb76d078c43b8ac0064e4a0164612b1\
                        fce77c869345bfc94c75894edd3315f5bdb76d078c43b8ac0064e4a0\
                        164612b1fce77c869345bfc94c75894edd3315f5bdb76d078c43b8ac0\
                        064e4a0164612b1fce77c869345bfc94c75894edd3315f5bdb76d078c4\
                        3b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3315f5bdb76d\
                        078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3315f5bd\
                        b76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd33"
            .as_bytes();
        let expected = "e39db0e4cc4d81ff74f04dda25d5e2ca3866776d2396fa6e73df1e94d2c14b70";
        let digest = sha256(msg);
        assert_eq!(expected, hex::encode(digest));
    }
}
