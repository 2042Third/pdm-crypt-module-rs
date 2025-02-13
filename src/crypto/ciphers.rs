use crate::crypto::configure::CryptoConfig;

const THREAD_COUNT: usize = 1;
const NONCE_SIZE: usize = 12;
const XNONCE_SIZE: usize = 16;

pub struct Crypto {
    config: CryptoConfig,
    nonce: Vec<u8>,
    nonce_orig: [u8; NONCE_SIZE],
    key: Vec<u8>,
    xcount: u64,
    count: u32,
    cy: [[u32; 16]; THREAD_COUNT],    // State arrays
    original_copy_state: [[u32; 16]; THREAD_COUNT],
}

impl Crypto {
    pub fn new(config: CryptoConfig) -> Self {
        Self {
            config,
            nonce: Vec::new(),
            nonce_orig: [0; NONCE_SIZE],
            key: Vec::new(),
            count: 0,
            xcount: 0,
            cy: [[0; 16]; THREAD_COUNT],
            original_copy_state: [[0; 16]; THREAD_COUNT],
        }
    }

    // Helper function for chacha20 setup
    fn h_set_vals(&mut self, nonce: &[u8], key: &[u8]) {
       self.count = 0;
    }

    // Function to expand state with data
    fn expand(state: &mut [u32], start_idx: usize, data: &[u8], len: usize) {
        let mut i = 0;
        let mut j = 0;

        while i < len {
            state[start_idx + i] = Crypto::bytes_to_u32(&data[j..j+4]);
            i += 1;
            j += 4;
        }
    }

    fn add_original_to_current(&mut self, thread: usize) {
        for i in 0..16 {
            self.cy[thread][i] = self.cy[thread][i].wrapping_add(self.original_copy_state[thread][i]);
        }
    }

    // Quater round operation
    fn quarter_round(x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
        x[a] = x[a].wrapping_add(x[b]); x[d] = x[d] ^ x[a]; x[d] = x[d].rotate_left(16);
        x[c] = x[c].wrapping_add(x[d]); x[b] = x[b] ^ x[c]; x[b] = x[b].rotate_left(12);
        x[a] = x[a].wrapping_add(x[b]); x[d] = x[d] ^ x[a]; x[d] = x[d].rotate_left(8);
        x[c] = x[c].wrapping_add(x[d]); x[b] = x[b] ^ x[c]; x[b] = x[b].rotate_left(7);
    }

    fn copy_current_to_original(&mut self, thread: usize) {
        self.original_copy_state[thread].copy_from_slice(&self.cy[thread]);
    }

    fn copy_original_to_current(&mut self, thread: usize) {
        self.cy[thread].copy_from_slice(&self.original_copy_state[thread]);
    }

    fn chacha20_block(&mut self, thread: usize) {
        // Copy state
        self.add_counter_to_original(thread);
        self.copy_original_to_current(thread);

        // Run 20 rounds
        for _ in 0..10 {
            self.two_rounds(thread);
        }

        // Add original state to current state
        self.add_original_to_current(thread);
    }

    fn cy_to_bytes(&self, thread: usize, output: &mut [u8]) {
        let mut i = 0;
        let mut j = 0;

        while i < 16 {
            output[j..j+4].copy_from_slice(&Crypto::u32_to_bytes(self.cy[thread][i]));
            i += 1;
            j += 4;
        }
    }

    /**
    2.4.1.  The ChaCha20 Encryption Algorithm in Pseudocode

     chacha20_encrypt(key, counter, nonce, plaintext):
        for j = 0 upto floor(len(plaintext)/64)-1
           key_stream = chacha20_block(key, counter+j, nonce)
           block = plaintext[(j*64)..(j*64+63)]
           encrypted_message +=  block ^ key_stream
           end
        if ((len(plaintext) % 64) != 0)
           j = floor(len(plaintext)/64)
           key_stream = chacha20_block(key, counter+j, nonce)
           block = plaintext[(j*64)..len(plaintext)-1]
           encrypted_message += (block^key_stream)[0..len(plaintext)%64]
           end
        return encrypted_message
        end

    */
    pub fn chacha20_encrypt(&mut self, thread: usize, plaintext: &[u8]) -> Vec<u8> {
        let mut encrypted_message: Vec<u8> = Vec::new();
        let mut key_stream: [u8;64] = [0; 64];
        let mut block: Vec<u8> = Vec::new();
        let mut j: usize = 0;

        for j in 0..(plaintext.len() / 64) {
            self.chacha20_block(thread);
            self.cy_to_bytes(thread, &mut key_stream);
            block = plaintext[j*64..j*64+64].to_vec();
            encrypted_message.extend(block.iter().zip(key_stream.iter()).map(|(a, b)| a ^ b));
        }

        if (plaintext.len() % 64) != 0 {
            j = plaintext.len() / 64;
            self.chacha20_block(thread);
            self.cy_to_bytes(thread, &mut key_stream);
            block = plaintext[j*64..plaintext.len()].to_vec();
            encrypted_message.extend(block.iter().zip(key_stream.iter()).map(|(a, b)| a ^ b));
        }

        encrypted_message
    }

    /**
       The ChaCha20 state is initialized as follows:

    o  The first four words (0-3) are constants: 0x61707865, 0x3320646e,
       0x79622d32, 0x6b206574.

    o  The next eight words (4-11) are taken from the 256-bit key by
       reading the bytes in little-endian order, in 4-byte chunks.

    o  Word 12 is a block counter.  Since each block is 64-byte, a 32-bit
       word is enough for 256 gigabytes of data.

    o  Words 13-15 are a nonce, which should not be repeated for the same
       key.  The 13th word is the first 32 bits of the input nonce taken
       as a little-endian integer, while the 15th word is the last 32
       bits.

        cccccccc  cccccccc  cccccccc  cccccccc
        kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
        kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
        bbbbbbbb  nnnnnnnn  nnnnnnnn  nnnnnnnn

    c=constant k=key b=blockcount n=nonce

    */
    pub fn chacha20_set_values(&mut self, nonce: &[u8], key: &[u8]) {
        // Store nonce
        self.nonce = nonce.to_vec();

        // Copy original nonce
        self.nonce_orig[..NONCE_SIZE].copy_from_slice(&nonce[..NONCE_SIZE]);

        self.count = 0;

        // Constants for ChaCha20
        const B1: u32 = 0x61707865; // "expa"
        const B2: u32 = 0x3320646e; // "nd 3"
        const B3: u32 = 0x79622d32; // "2-by"
        const B4: u32 = 0x6b206574; // "te k"

        for i in 0..THREAD_COUNT {
            // // XChaCha subkey setup
            // self.cy[i][4] = self.cy[i][0];
            // self.cy[i][5] = self.cy[i][1];
            // self.cy[i][6] = self.cy[i][2];
            // self.cy[i][7] = self.cy[i][3];
            // self.cy[i][8] = self.cy[i][12];
            // self.cy[i][9] = self.cy[i][13];
            // self.cy[i][10] = self.cy[i][14];
            // self.cy[i][11] = self.cy[i][15];

            // Set constants
            self.cy[i][0] = B1;
            self.cy[i][1] = B2;
            self.cy[i][2] = B3;
            self.cy[i][3] = B4;

            // Expand the state with nonce and key
            Self::expand(&mut self.cy[i], 13, nonce, 3); // chacha20 nonce, xchacha20 changes this
            Self::expand(&mut self.cy[i], 4, key, 8);

            self.cy[i][12] = 0; // in chacha20, this is the only counter
            // self.cy[i][13] = 1; // in chacha20, this is not the counter

            self.copy_current_to_original(i);
        }
    }

    /**
    ChaCha20 runs 20 rounds, alternating between "column rounds" and
    "diagonal rounds".  Each round consists of four quarter-rounds, and
    they are run as follows.  Quarter rounds 1-4 are part of a "column"
    round, while 5-8 are part of a "diagonal" round:

    1.  QUARTERROUND ( 0, 4, 8,12)
    2.  QUARTERROUND ( 1, 5, 9,13)
    3.  QUARTERROUND ( 2, 6,10,14)
    4.  QUARTERROUND ( 3, 7,11,15)
    5.  QUARTERROUND ( 0, 5,10,15)
    6.  QUARTERROUND ( 1, 6,11,12)
    7.  QUARTERROUND ( 2, 7, 8,13)
    8.  QUARTERROUND ( 3, 4, 9,14)
    */
    pub fn two_rounds(&mut self, thread: usize) {
        Crypto::quarter_round(&mut self.cy[thread], 0, 4, 8, 12);
        Crypto::quarter_round(&mut self.cy[thread], 1, 5, 9, 13);
        Crypto::quarter_round(&mut self.cy[thread], 2, 6, 10, 14);
        Crypto::quarter_round(&mut self.cy[thread], 3, 7, 11, 15);
        Crypto::quarter_round(&mut self.cy[thread], 0, 5, 10, 15);
        Crypto::quarter_round(&mut self.cy[thread], 1, 6, 11, 12);
        Crypto::quarter_round(&mut self.cy[thread], 2, 7, 8, 13);
        Crypto::quarter_round(&mut self.cy[thread], 3, 4, 9, 14);
    }

    pub fn add_counter_to_original(&mut self, thread: usize) {
        self.count += 1;
        self.original_copy_state[thread][12] = self.count;
    }

    // Convert between bytes and u32s
    pub fn bytes_to_u32(input: &[u8]) -> u32 {
        u32::from_le_bytes([input[0], input[1], input[2], input[3]])
    }

    pub fn u32_to_bytes(input: u32) -> [u8; 4] {
        input.to_le_bytes()
    }

    // Rotate left operation for ChaCha20
    pub fn rotl(a: u32, b: u32) -> u32 {
        (a << b) | (a >> (32 - b))
    }
}

// Test module
#[cfg(test)]
mod tests {
    use super::*;  // Import everything from parent module


    /**
    2.4.2.  Example and Test Vector for the ChaCha20 Cipher

       For a test vector, we will use the following inputs to the ChaCha20
       block function:

       o  Key = 00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:
          14:15:16:17:18:19:1a:1b:1c:1d:1e:1f.

       o  Nonce = (00:00:00:00:00:00:00:4a:00:00:00:00).

       o  Initial Counter = 1.

       We use the following for the plaintext.  It was chosen to be long
       enough to require more than one block, but not so long that it would
       make this example cumbersome (so, less than 3 blocks):

      Plaintext Sunscreen:
      000  4c 61 64 69 65 73 20 61 6e 64 20 47 65 6e 74 6c  Ladies and Gentl
      016  65 6d 65 6e 20 6f 66 20 74 68 65 20 63 6c 61 73  emen of the clas
      032  73 20 6f 66 20 27 39 39 3a 20 49 66 20 49 20 63  s of '99: If I c
      048  6f 75 6c 64 20 6f 66 66 65 72 20 79 6f 75 20 6f  ould offer you o
      064  6e 6c 79 20 6f 6e 65 20 74 69 70 20 66 6f 72 20  nly one tip for
      080  74 68 65 20 66 75 74 75 72 65 2c 20 73 75 6e 73  the future, suns
      096  63 72 65 65 6e 20 77 6f 75 6c 64 20 62 65 20 69  creen would be i
      112  74 2e                                            t.

       The following figure shows four ChaCha state matrices:

       1.  First block as it is set up.

       2.  Second block as it is set up.  Note that these blocks are only
           two bits apart -- only the counter in position 12 is different.

       3.  Third block is the first block after the ChaCha20 block
           operation.

       4.  Final block is the second block after the ChaCha20 block
           operation was applied.

       After that, we show the keystream.

       First block setup:
           61707865  3320646e  79622d32  6b206574
           03020100  07060504  0b0a0908  0f0e0d0c
           13121110  17161514  1b1a1918  1f1e1d1c
           00000001  00000000  4a000000  00000000

       Second block setup:
           61707865  3320646e  79622d32  6b206574
           03020100  07060504  0b0a0908  0f0e0d0c
           13121110  17161514  1b1a1918  1f1e1d1c
           00000002  00000000  4a000000  00000000

       First block after block operation:
           f3514f22  e1d91b40  6f27de2f  ed1d63b8
           821f138c  e2062c3d  ecca4f7e  78cff39e
           a30a3b8a  920a6072  cd7479b5  34932bed
           40ba4c79  cd343ec6  4c2c21ea  b7417df0

        Second block after block operation:
            9f74a669  410f633f  28feca22  7ec44dec
            6d34d426  738cb970  3ac5e9f3  45590cc4
            da6e8b39  892c831a  cdea67c1  2b7e1d90
            037463f3  a11a2073  e8bcfb88  edc49139

        Keystream:
        22:4f:51:f3:40:1b:d9:e1:2f:de:27:6f:b8:63:1d:ed:8c:13:1f:82:3d:2c:06
        e2:7e:4f:ca:ec:9e:f3:cf:78:8a:3b:0a:a3:72:60:0a:92:b5:79:74:cd:ed:2b
        93:34:79:4c:ba:40:c6:3e:34:cd:ea:21:2c:4c:f0:7d:41:b7:69:a6:74:9f:3f
        63:0f:41:22:ca:fe:28:ec:4d:c4:7e:26:d4:34:6d:70:b9:8c:73:f3:e9:c5:3a
        c4:0c:59:45:39:8b:6e:da:1a:83:2c:89:c1:67:ea:cd:90:1d:7e:2b:f3:63

       Finally, we XOR the keystream with the plaintext, yielding the
         ciphertext:

        Ciphertext Sunscreen:
        000  6e 2e 35 9a 25 68 f9 80 41 ba 07 28 dd 0d 69 81  n.5.%h..A..(..i.
        016  e9 7e 7a ec 1d 43 60 c2 0a 27 af cc fd 9f ae 0b  .~z..C`..'......
        032  f9 1b 65 c5 52 47 33 ab 8f 59 3d ab cd 62 b3 57  ..e.RG3..Y=..b.W
        048  16 39 d6 24 e6 51 52 ab 8f 53 0c 35 9f 08 61 d8  .9.$.QR..S.5..a.
        064  07 ca 0d bf 50 0d 6a 61 56 a3 8e 08 8a 22 b6 5e  ....P.jaV....".^
        080  52 bc 51 4d 16 cc f8 06 81 8c e9 1a b7 79 37 36  R.QM.........y76
        096  5a f9 0b bf 74 a3 5b e6 b4 0b 8e ed f2 78 5e 42  Z...t.[......x^B
        112  87 4d
    */
    #[test]
    fn test_chacha20_block() {
        let config = CryptoConfig::new().with_de(false)
            .with_display_prog(false)
            .with_poly1305(false)
            .with_pure_xor(false)
            .with_xchacha(false);
        let mut crypto = Crypto::new(config);

        let mut nonce: [u8; 12] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00
        ];

        let mut key :[u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
        ];

        crypto.chacha20_set_values(&nonce, &key);

        crypto.chacha20_block(0);

        assert_eq!(crypto.cy[0], [
            0xf3514f22, 0xe1d91b40, 0x6f27de2f, 0xed1d63b8,
            0x821f138c, 0xe2062c3d, 0xecca4f7e, 0x78cff39e,
            0xa30a3b8a, 0x920a6072, 0xcd7479b5, 0x34932bed,
            0x40ba4c79, 0xcd343ec6, 0x4c2c21ea, 0xb7417df0,
        ]);

        crypto.chacha20_block(0);

        assert_eq!(crypto.cy[0], [
            0x9f74a669, 0x410f633f, 0x28feca22, 0x7ec44dec,
            0x6d34d426, 0x738cb970, 0x3ac5e9f3, 0x45590cc4,
            0xda6e8b39, 0x892c831a, 0xcdea67c1, 0x2b7e1d90,
            0x037463f3, 0xa11a2073, 0xe8bcfb88, 0xedc49139,
        ]);
    }

    #[test]
    fn test_chacha20_encrypt() {
        let config = CryptoConfig::new().with_de(false)
            .with_display_prog(false)
            .with_poly1305(false)
            .with_pure_xor(false)
            .with_xchacha(false);
        let mut crypto = Crypto::new(config);

        let mut nonce: [u8; 12] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00
        ];

        let mut key :[u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
        ];

        let plain_text = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".as_bytes();

        crypto.chacha20_set_values(&nonce, &key);

        let encrypted = crypto.chacha20_encrypt(0,plain_text);

        assert_eq!(encrypted, [
            0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81,
            0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2, 0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b,
            0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab, 0x8f, 0x59, 0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57,
            0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab, 0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8,
            0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61, 0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e,
            0x52, 0xbc, 0x51, 0x4d, 0x16, 0xcc, 0xf8, 0x06, 0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36,
            0x5a, 0xf9, 0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6, 0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
            0x87, 0x4d
        ]);
    }

    /**
    2.3.2.  Test Vector for the ChaCha20 Block Function

    For a test vector, we will use the following inputs to the ChaCha20
    block function:

    o  Key = 00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:
       14:15:16:17:18:19:1a:1b:1c:1d:1e:1f.  The key is a sequence of
       octets with no particular structure before we copy it into the
       ChaCha state.

    o  Nonce = (00:00:00:09:00:00:00:4a:00:00:00:00)

    o  Block Count = 1.

    After setting up the ChaCha state, it looks like this:

    ChaCha state with the key setup.

        61707865  3320646e  79622d32  6b206574
        03020100  07060504  0b0a0908  0f0e0d0c
        13121110  17161514  1b1a1918  1f1e1d1c
        00000001  09000000  4a000000  00000000

    */
    #[test]
    fn test_set_values() {
        let config = CryptoConfig::new().with_de(false)
                                        .with_display_prog(false)
                                        .with_poly1305(false)
                                        .with_pure_xor(false)
                                        .with_xchacha(false);
        let mut crypto = Crypto::new(config);

        let mut u32key : [u32; 8] = [0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c, 0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c];

        let mut nonce:[u8;12] = [
            0x00, 0x00, 0x00, 0x09,  // First 4 bytes
            0x00, 0x00, 0x00, 0x4a,  // Next 4 bytes (0x4a is 74 in decimal)
            0x00, 0x00, 0x00, 0x00   // Last 4 bytes
        ];

        assert_eq!(nonce, [
            0x00, 0x00, 0x00, 0x09,
            0x00, 0x00, 0x00, 0x4a,
            0x00, 0x00, 0x00, 0x00
        ]);

        let mut key:[u8; 32] = [0; 32];
        for i in 0..8 {
            key[i*4..(i+1)*4].copy_from_slice(&u32key[i].to_le_bytes());
        }

        assert_eq!(key, [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ]);

        crypto.chacha20_set_values(&nonce, &key);
        crypto.add_counter_to_original(0);

        assert_eq!(crypto.original_copy_state[0], [
            0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
            0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
            0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
            0x00000001, 0x09000000, 0x4a000000, 0x00000000,
        ]);
    }



    /**
    After running 20 rounds (10 column rounds interleaved with 10
    "diagonal rounds"), the ChaCha state looks like this:

    ChaCha state after 20 rounds

        837778ab  e238d763  a67ae21e  5950bb2f
        c4f2d0c7  fc62bb2f  8fa018fc  3f5ec7b7
        335271c2  f29489f3  eabda8fc  82e46ebd
        d19c12b4  b04e16de  9e83d0cb  4e3c50a2

    Finally, we add the original state to the result (simple vector or
    matrix addition), giving this:

    ChaCha state at the end of the ChaCha20 operation

        e4e7f110  15593bd1  1fdd0f50  c47120a3
        c7f4d1c7  0368c033  9aaa2204  4e6cd4c3
        466482d2  09aa9f07  05d7c214  a2028bd9
        d19c12b5  b94e16de  e883d0cb  4e3c50a2
    */
    #[test]
    fn test_two_rounds () {
        let config = CryptoConfig::new().with_de(false)
            .with_display_prog(false)
            .with_poly1305(false)
            .with_pure_xor(false)
            .with_xchacha(false);
        let mut crypto = Crypto::new(config);

        let mut u32key : [u32; 8] = [0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c, 0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c];

        let mut nonce:[u8;12] = [
            0x00, 0x00, 0x00, 0x09,  // First 4 bytes
            0x00, 0x00, 0x00, 0x4a,  // Next 4 bytes (0x4a is 74 in decimal)
            0x00, 0x00, 0x00, 0x00   // Last 4 bytes
        ];

        let mut key:[u8; 32] = [0; 32];
        for i in 0..8 {
            key[i*4..(i+1)*4].copy_from_slice(&u32key[i].to_le_bytes());
        }

        crypto.chacha20_set_values(&nonce, &key);

        crypto.add_counter_to_original(0);
        crypto.copy_original_to_current(0);

        // Run 20 rounds
        crypto.two_rounds(0);
        crypto.two_rounds(0);
        crypto.two_rounds(0);
        crypto.two_rounds(0);
        crypto.two_rounds(0);
        crypto.two_rounds(0);
        crypto.two_rounds(0);
        crypto.two_rounds(0);
        crypto.two_rounds(0);
        crypto.two_rounds(0);

        assert_eq!(crypto.cy[0], [
            0x837778ab, 0xe238d763, 0xa67ae21e, 0x5950bb2f,
            0xc4f2d0c7, 0xfc62bb2f, 0x8fa018fc, 0x3f5ec7b7,
            0x335271c2, 0xf29489f3, 0xeabda8fc, 0x82e46ebd,
            0xd19c12b4, 0xb04e16de, 0x9e83d0cb, 0x4e3c50a2,
        ]);

        crypto.add_original_to_current(0);

        assert_eq!(crypto.cy[0], [
            0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3,
            0xc7f4d1c7, 0x0368c033, 0x9aaa2204, 0x4e6cd4c3,
            0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9,
            0xd19c12b5, 0xb94e16de, 0xe883d0cb, 0x4e3c50a2,
        ]);
    }

    #[test]
    /**
    After running 20 rounds (10 column rounds interleaved with 10
    "diagonal rounds"), the ChaCha state looks like this:

    ChaCha state after 20 rounds

        837778ab  e238d763  a67ae21e  5950bb2f
        c4f2d0c7  fc62bb2f  8fa018fc  3f5ec7b7
        335271c2  f29489f3  eabda8fc  82e46ebd
        d19c12b4  b04e16de  9e83d0cb  4e3c50a2

    Finally, we add the original state to the result (simple vector or
    matrix addition), giving this:

    ChaCha state at the end of the ChaCha20 operation

        e4e7f110  15593bd1  1fdd0f50  c47120a3
        c7f4d1c7  0368c033  9aaa2204  4e6cd4c3
        466482d2  09aa9f07  05d7c214  a2028bd9
        d19c12b5  b94e16de  e883d0cb  4e3c50a2
    */
    fn test_two_rounds_function () {
        let config = CryptoConfig::new().with_de(false)
            .with_display_prog(false)
            .with_poly1305(false)
            .with_pure_xor(false)
            .with_xchacha(false);
        let mut crypto = Crypto::new(config);

        let mut u32nonce : [u32; 3] = [0x09000000, 0x4a000000, 0x00000000];
        let mut u32key : [u32; 8] = [0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c, 0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c];

        let mut nonce:[u8;12] = [
            0x00, 0x00, 0x00, 0x09,  // First 4 bytes
            0x00, 0x00, 0x00, 0x4a,  // Next 4 bytes (0x4a is 74 in decimal)
            0x00, 0x00, 0x00, 0x00   // Last 4 bytes
        ];

        let mut key:[u8; 32] = [0; 32];
        for i in 0..8 {
            key[i*4..(i+1)*4].copy_from_slice(&u32key[i].to_le_bytes());
        }

        crypto.chacha20_set_values(&nonce, &key);

        crypto.chacha20_block(0);

        assert_eq!(crypto.cy[0], [
            0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3,
            0xc7f4d1c7, 0x0368c033, 0x9aaa2204, 0x4e6cd4c3,
            0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9,
            0xd19c12b5, 0xb94e16de, 0xe883d0cb, 0x4e3c50a2,
        ]);
    }

    #[test]
    fn test_quarter_round_basic() {
        // Test case from the ChaCha20 specification
        // https://tools.ietf.org/html/rfc8439#section-2.2.1
        let mut state: [u32; 16] = [
            0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567,
            0,0,0,0,
            0,0,0,0,
            0,0,0,0,
        ];

        Crypto::quarter_round(&mut state,0, 1, 2, 3);

        assert_eq!(state, [
            0xea2a92f4, 0xcb1cf8ce, 0x4581472e, 0x5881c4bb,
            0,0,0,0,
            0,0,0,0,
            0,0,0,0,
        ]);
    }


    /**
    RFC 7539 Test Vectors
    --------------------------------
    2.2.1.  Test Vector for the Quarter Round on the ChaCha State

    For a test vector, we will use a ChaCha state that was generated
    randomly:

    Sample ChaCha State

        879531e0  c5ecf37d  516461b1  c9a62f8a
        44c20ef3  3390af7f  d9fc690b  2a5f714c
        53372767  b00a5631  974c541a  359e9963
        5c971061  3d631689  2098d9d6  91dbd320

    We will apply the QUARTERROUND(2,7,8,13) operation to this state.
    For obvious reasons, this one is part of what is called a "diagonal
    round":

    After applying QUARTERROUND(2,7,8,13)

        879531e0  c5ecf37d *bdb886dc  c9a62f8a
        44c20ef3  3390af7f  d9fc690b *cfacafd2
       *e46bea80  b00a5631  974c541a  359e9963
        5c971061 *ccc07c79  2098d9d6  91dbd320

    Note that only the numbers in positions 2, 7, 8, and 13 changed.
    --------------------------------
    */
    #[test]
    fn test_quarter_round_rfc7539() {
        let mut state:[u32;16] = [
            0x879531e0,  0xc5ecf37d,  0x516461b1,  0xc9a62f8a,
            0x44c20ef3,  0x3390af7f,  0xd9fc690b,  0x2a5f714c,
            0x53372767,  0xb00a5631,  0x974c541a,  0x359e9963,
            0x5c971061,  0x3d631689,  0x2098d9d6,  0x91dbd320,
        ];

        Crypto::quarter_round(&mut state, 2, 7, 8, 13);

        assert_eq!(state, [
            0x879531e0,  0xc5ecf37d,  0xbdb886dc,  0xc9a62f8a,
            0x44c20ef3,  0x3390af7f,  0xd9fc690b,  0xcfacafd2,
            0xe46bea80,  0xb00a5631,  0x974c541a,  0x359e9963,
            0x5c971061,  0xccc07c79,  0x2098d9d6,  0x91dbd320,
        ]);
    }
}
