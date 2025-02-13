// Copyright 2016 chacha20-poly1305-aead Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

// The 130-bit accumulator is split into five 26-bit limbs, with the
// carry between the limbs delayed.
//
// The reduction steps use the following identity:
//
// a×2^n ≡ a×c (mod 2^n−c)
//
// For Poly1305, the identity becomes:
//
// a×2^130 ≡ a×5 (mod 2^130−5)
//
// That is, any limb or carry above 2^130 is multiplied by 5 and added
// back to the lower limbs.
//
// Based on the algorithm from https://github.com/floodyberry/poly1305-donna

#[derive(Clone, Debug)]
pub struct Poly1305 {
    /// Accumulator: 5x26-bit
    a: [u32; 5],
    /// Multiplier: 5x26-bit
    r: [u32; 5],
    /// Secret key: 4x32-bit
    s: [u32; 4],
}

impl Poly1305 {
    pub fn new(key: &[u8]) -> Self {
        assert!(key.len() == 32);

        Poly1305 {
            a: [0; 5],

            // r &= 0x0ffffffc_0ffffffc_0ffffffc_0fffffff;
            r: [u32_from_le(&key[ 0.. 4])      & 0x03ffffff,
                u32_from_le(&key[ 3.. 7]) >> 2 & 0x03ffff03,
                u32_from_le(&key[ 6..10]) >> 4 & 0x03ffc0ff,
                u32_from_le(&key[ 9..13]) >> 6 & 0x03f03fff,
                u32_from_le(&key[12..16]) >> 8 & 0x000fffff],

            s: [u32_from_le(&key[16..20]),
                u32_from_le(&key[20..24]),
                u32_from_le(&key[24..28]),
                u32_from_le(&key[28..32])],
        }
    }

    pub fn block(&mut self, msg: &[u8]) {
        assert!(msg.len() == 16);
        self.accumulate(u32_from_le(&msg[ 0.. 4])      & 0x03ffffff,
                        u32_from_le(&msg[ 3.. 7]) >> 2 & 0x03ffffff,
                        u32_from_le(&msg[ 6..10]) >> 4 & 0x03ffffff,
                        u32_from_le(&msg[ 9..13]) >> 6 & 0x03ffffff,
                        u32_from_le(&msg[12..16]) >> 8 | (1 <<  24));
    }

    pub fn last_block(mut self, msg: &[u8]) -> [u32; 4] {
        if !msg.is_empty() {
            assert!(msg.len() <= 16);

            let mut buf = [0; 17];
            buf[..msg.len()].clone_from_slice(msg);
            buf[msg.len()] = 1;

            self.accumulate(u32_from_le(&buf[ 0.. 4])      & 0x03ffffff,
                            u32_from_le(&buf[ 3.. 7]) >> 2 & 0x03ffffff,
                            u32_from_le(&buf[ 6..10]) >> 4 & 0x03ffffff,
                            u32_from_le(&buf[ 9..13]) >> 6 & 0x03ffffff,
                            u32_from_le(&buf[13..17]));
        }

        self.tag()
    }

    fn padded_block(&mut self, msg: &[u8]) {
        assert!(msg.len() <= 16);
        let mut buf = [0; 16];
        buf[..msg.len()].clone_from_slice(msg);
        self.block(&buf);
    }

    pub fn padded_blocks(&mut self, mut msg: &[u8]) {
        while msg.len() >= 16 {
            self.block(&msg[..16]);
            msg = &msg[16..];
        }
        if !msg.is_empty() {
            self.padded_block(msg);
        }
    }

    fn accumulate(&mut self, n0: u32, n1: u32, n2: u32, n3: u32, n4: u32) {
        self.a[0] += n0;
        self.a[1] += n1;
        self.a[2] += n2;
        self.a[3] += n3;
        self.a[4] += n4;
        self.mul_r_mod_p();
    }

    // #[cfg_attr(feature = "clippy", allow(cast_possible_truncation))]
    fn mul_r_mod_p(&mut self) {
        // t = r * a; high limbs multiplied by 5 and added to low limbs
        let mut t = [0; 5];

        t[0] +=      self.r[0]  as u64 * self.a[0] as u64;
        t[1] +=      self.r[0]  as u64 * self.a[1] as u64;
        t[2] +=      self.r[0]  as u64 * self.a[2] as u64;
        t[3] +=      self.r[0]  as u64 * self.a[3] as u64;
        t[4] +=      self.r[0]  as u64 * self.a[4] as u64;

        t[0] += (5 * self.r[1]) as u64 * self.a[4] as u64;
        t[1] +=      self.r[1]  as u64 * self.a[0] as u64;
        t[2] +=      self.r[1]  as u64 * self.a[1] as u64;
        t[3] +=      self.r[1]  as u64 * self.a[2] as u64;
        t[4] +=      self.r[1]  as u64 * self.a[3] as u64;

        t[0] += (5 * self.r[2]) as u64 * self.a[3] as u64;
        t[1] += (5 * self.r[2]) as u64 * self.a[4] as u64;
        t[2] +=      self.r[2]  as u64 * self.a[0] as u64;
        t[3] +=      self.r[2]  as u64 * self.a[1] as u64;
        t[4] +=      self.r[2]  as u64 * self.a[2] as u64;

        t[0] += (5 * self.r[3]) as u64 * self.a[2] as u64;
        t[1] += (5 * self.r[3]) as u64 * self.a[3] as u64;
        t[2] += (5 * self.r[3]) as u64 * self.a[4] as u64;
        t[3] +=      self.r[3]  as u64 * self.a[0] as u64;
        t[4] +=      self.r[3]  as u64 * self.a[1] as u64;

        t[0] += (5 * self.r[4]) as u64 * self.a[1] as u64;
        t[1] += (5 * self.r[4]) as u64 * self.a[2] as u64;
        t[2] += (5 * self.r[4]) as u64 * self.a[3] as u64;
        t[3] += (5 * self.r[4]) as u64 * self.a[4] as u64;
        t[4] +=      self.r[4]  as u64 * self.a[0] as u64;

        // propagate carries
        t[1] += t[0] >> 26;
        t[2] += t[1] >> 26;
        t[3] += t[2] >> 26;
        t[4] += t[3] >> 26;

        // mask out carries
        self.a[0] = t[0] as u32 & 0x03ffffff;
        self.a[1] = t[1] as u32 & 0x03ffffff;
        self.a[2] = t[2] as u32 & 0x03ffffff;
        self.a[3] = t[3] as u32 & 0x03ffffff;
        self.a[4] = t[4] as u32 & 0x03ffffff;

        // propagate high limb carry
        self.a[0] += (t[4] >> 26) as u32 * 5;
        self.a[1] += self.a[0] >> 26;

        // mask out carries
        self.a[0] &= 0x03ffffff;

        // A carry of at most 1 bit has been left in self.a[1]
    }

    fn propagate_carries(&mut self) {
        // propagate carries
        self.a[2] +=  self.a[1] >> 26;
        self.a[3] +=  self.a[2] >> 26;
        self.a[4] +=  self.a[3] >> 26;
        self.a[0] += (self.a[4] >> 26) * 5;
        self.a[1] +=  self.a[0] >> 26;

        // mask out carries
        self.a[0] &= 0x03ffffff;
        self.a[1] &= 0x03ffffff;
        self.a[2] &= 0x03ffffff;
        self.a[3] &= 0x03ffffff;
        self.a[4] &= 0x03ffffff;
    }

    fn reduce_mod_p(&mut self) {
        self.propagate_carries();

        let mut t = self.a;

        // t = a - p
        t[0] += 5;
        t[4]  = t[4].wrapping_sub(1 << 26);

        // propagate carries
        t[1] +=                   t[0] >> 26;
        t[2] +=                   t[1] >> 26;
        t[3] +=                   t[2] >> 26;
        t[4]  = t[4].wrapping_add(t[3] >> 26);

        // mask out carries
        t[0] &= 0x03ffffff;
        t[1] &= 0x03ffffff;
        t[2] &= 0x03ffffff;
        t[3] &= 0x03ffffff;

        // constant-time select between (a - p) if non-negative, (a) otherwise
        let mask = (t[4] >> 31).wrapping_sub(1);
        self.a[0] = t[0] & mask | self.a[0] & !mask;
        self.a[1] = t[1] & mask | self.a[1] & !mask;
        self.a[2] = t[2] & mask | self.a[2] & !mask;
        self.a[3] = t[3] & mask | self.a[3] & !mask;
        self.a[4] = t[4] & mask | self.a[4] & !mask;
    }

    #[cfg_attr(feature = "clippy", allow(cast_possible_truncation))]
    pub fn tag(mut self) -> [u32; 4] {
        self.reduce_mod_p();

        // convert from 5x26-bit to 4x32-bit
        let a = [self.a[0]       | self.a[1] << 26,
            self.a[1] >>  6 | self.a[2] << 20,
            self.a[2] >> 12 | self.a[3] << 14,
            self.a[3] >> 18 | self.a[4] <<  8];

        // t = a + s
        let mut t = [a[0] as u64 + self.s[0] as u64,
            a[1] as u64 + self.s[1] as u64,
            a[2] as u64 + self.s[2] as u64,
            a[3] as u64 + self.s[3] as u64];

        // propagate carries
        t[1] += t[0] >> 32;
        t[2] += t[1] >> 32;
        t[3] += t[2] >> 32;

        // mask out carries
        [(t[0] as u32).to_le(),
            (t[1] as u32).to_le(),
            (t[2] as u32).to_le(),
            (t[3] as u32).to_le()]
    }
}

#[inline]
fn u32_from_le(src: &[u8]) -> u32 {
    assert!(src.len() == 4);
    let array: [u8; 4] = src.try_into().unwrap();
    u32::from_le_bytes(array)
}



// Test module
#[cfg(test)]
mod tests {
    use crate::crypto::Crypto;
    use super::*;  // Import everything from parent module

    /**
    2.5.2.  Poly1305 Example and Test Vector

    For our example, we will dispense with generating the one-time key
    using AES, and assume that we got the following keying material:

    o  Key Material: 85:d6:be:78:57:55:6d:33:7f:44:52:fe:42:d5:06:a8:01:0
       3:80:8a:fb:0d:b2:fd:4a:bf:f6:af:41:49:f5:1b

    o  s as an octet string:
       01:03:80:8a:fb:0d:b2:fd:4a:bf:f6:af:41:49:f5:1b

     o  s as a 128-bit number: 1bf54941aff6bf4afdb20dfb8a800301

     o  r before clamping: 85:d6:be:78:57:55:6d:33:7f:44:52:fe:42:d5:06:a8

     o  Clamped r as a number: 806d5400e52447c036d555408bed685

     For our message, we'll use a short text:

    Message to be Authenticated:
    000  43 72 79 70 74 6f 67 72 61 70 68 69 63 20 46 6f  Cryptographic Fo
    016  72 75 6d 20 52 65 73 65 61 72 63 68 20 47 72 6f  rum Research Gro
    032  75 70                                            up

     Since Poly1305 works in 16-byte chunks, the 34-byte message divides
     into three blocks.  In the following calculation, "Acc" denotes the
     accumulator and "Block" the current block:

     Block #1

     Acc = 00
     Block = 6f4620636968706172676f7470797243
     Block with 0x01 byte = 016f4620636968706172676f7470797243
     Acc + block = 016f4620636968706172676f7470797243
     (Acc+Block) * r =
          b83fe991ca66800489155dcd69e8426ba2779453994ac90ed284034da565ecf
     Acc = ((Acc+Block)*r) % P = 2c88c77849d64ae9147ddeb88e69c83fc

     Block #2

     Acc = 2c88c77849d64ae9147ddeb88e69c83fc
     Block = 6f7247206863726165736552206d7572
     Block with 0x01 byte = 016f7247206863726165736552206d7572
     Acc + block = 437febea505c820f2ad5150db0709f96e
     (Acc+Block) * r =
          21dcc992d0c659ba4036f65bb7f88562ae59b32c2b3b8f7efc8b00f78e548a26
     Acc = ((Acc+Block)*r) % P = 2d8adaf23b0337fa7cccfb4ea344b30de

     Last Block

     Acc = 2d8adaf23b0337fa7cccfb4ea344b30de
     Block = 7075
     Block with 0x01 byte = 017075
     Acc + block = 2d8adaf23b0337fa7cccfb4ea344ca153
     (Acc + Block) * r =
          16d8e08a0f3fe1de4fe4a15486aca7a270a29f1e6c849221e4a6798b8e45321f
     ((Acc + Block) * r) % P = 28d31b7caff946c77c8844335369d03a7

    Adding s, we get this number, and serialize if to get the tag:

    Acc + s = 2a927010caf8b2bc2c6365130c11d06a8

    Tag: a8:06:1d:c1:30:51:36:c6:c2:2b:8b:af:0c:01:27:a9

    */

    #[test]
    fn test_poly1305() {
        let key = [
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
            0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
            0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
            0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b,
        ];

        let msg = b"Cryptographic Forum Research Group";

        let expected:[u8;16] = [0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6,
            0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9];


        let mut poly = Poly1305::new(&key);
        poly.padded_blocks(&msg[0..16]);
        poly.padded_blocks(&msg[16..32]);
        let tag = poly.last_block(&msg[32..]);

        let mut output: [u8;16] = [0;16];

        for i in 0..4 {
            let x = Crypto::u32_to_bytes(tag[i]);
            output[i*4] = x[0];
            output[i*4+1] = x[1];
            output[i*4+2] = x[2];
            output[i*4+3] = x[3];
        }

        assert_eq!( output, expected);

    }


}
