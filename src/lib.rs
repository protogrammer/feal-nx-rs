use std::mem::{transmute, MaybeUninit};

pub type Key = [u8; 16];
const N: usize = 32;
type ExtendedKey = [u16; N + 8];

pub struct FealNx {
    x_key: ExtendedKey,
}

impl FealNx {
    pub fn new(key: &Key) -> Self {
        FealNx {
            x_key: extend_key(key),
        }
    }

    pub fn encrypt(&self, value: u64) -> u64 {
        let mut l = (value >> 32) as u32;
        let mut r = (value & 0xffffffff) as u32;

        // pre-processing
        l ^= self.x_key[N + 1] as u32 | (self.x_key[N] as u32) << 16;
        r ^= l ^ (self.x_key[N + 3] as u32 | (self.x_key[N + 2] as u32) << 16);

        // iterative calculation
        for k in self.x_key[..N].iter().cloned() {
            (l, r) = (r, l ^ f(r, k));
        }

        // post-processing
        l ^= r ^ (self.x_key[N + 7] as u32 | (self.x_key[N + 6] as u32) << 16);
        r ^= self.x_key[N + 5] as u32 | (self.x_key[N + 4] as u32) << 16;

        l as u64 | (r as u64) << 32
    }

    pub fn decrypt(&self, value: u64) -> u64 {
        let mut r = (value >> 32) as u32;
        let mut l = (value & 0xffffffff) as u32;

        // pre-processing
        r ^= self.x_key[N + 5] as u32 | (self.x_key[N + 4] as u32) << 16;
        l ^= r ^ (self.x_key[N + 7] as u32 | (self.x_key[N + 6] as u32) << 16);

        // iterative calculation
        for k in self.x_key[..N].iter().rev().cloned() {
            (r, l) = (l, r ^ f(l, k));
        }

        // post-processing
        r ^= l ^ (self.x_key[N + 3] as u32 | (self.x_key[N + 2] as u32) << 16);
        l ^= self.x_key[N + 1] as u32 | (self.x_key[N] as u32) << 16;

        r as u64 | (l as u64) << 32
    }
}

fn extend_key(key: &Key) -> ExtendedKey {
    let key_left: u64 = u64::from_be_bytes(unsafe { (&key[8..16]).try_into().unwrap_unchecked() });
    let key_right: u64 = u64::from_be_bytes(unsafe { (&key[..8]).try_into().unwrap_unchecked() });

    let key_right_1 = (key_right >> 32) as u32;
    let key_right_2 = (key_right & 0xffffffff) as u32;
    let q_slice = [key_right_1 ^ key_right_2, key_right_1, key_right_2];

    let mut a = (key_left >> 32) as u32;
    let mut b = (key_left & 0xffffffff) as u32;
    let mut d: u32 = 0;

    let mut x_key: [MaybeUninit<u16>; N + 8] = unsafe { MaybeUninit::uninit().assume_init() };

    for (r, q) in (0..N / 2 + 4).zip(q_slice.into_iter().cycle()) {
        (d, a, b) = (a, b, fk(a, b ^ d ^ q));
        x_key[2 * r].write((b >> 16) as u16);
        x_key[2 * r + 1].write((b & 0xffff) as u16);
    }

    unsafe { transmute(x_key) }
}

fn f(alpha: u32, beta: u16) -> u32 {
    let a = alpha.to_be_bytes();
    let b = beta.to_be_bytes();

    let mut f: [MaybeUninit<u8>; 4] = unsafe { MaybeUninit::uninit().assume_init() };

    f[1].write(a[1] ^ b[0]);
    f[2].write(a[2] ^ b[1]);
    f[1].write(unsafe { f[1].assume_init() } ^ a[0]);
    f[2].write(unsafe { f[2].assume_init() } ^ a[3]);
    f[1].write(s1(unsafe { f[1].assume_init() }, unsafe {
        f[2].assume_init()
    }));
    f[2].write(s0(unsafe { f[2].assume_init() }, unsafe {
        f[1].assume_init()
    }));
    f[0].write(s0(a[0], unsafe { f[1].assume_init() }));
    f[3].write(s1(a[3], unsafe { f[2].assume_init() }));

    u32::from_be_bytes(unsafe { transmute(f) })
}

fn fk(alpha: u32, beta: u32) -> u32 {
    let a = alpha.to_be_bytes();
    let b = beta.to_be_bytes();

    let mut f: [MaybeUninit<u8>; 4] = unsafe { MaybeUninit::uninit().assume_init() };

    f[1].write(a[1] ^ a[0]);
    f[2].write(a[2] ^ a[3]);
    f[1].write(s1(
        unsafe { f[1].assume_init() },
        unsafe { f[2].assume_init() } ^ b[0],
    ));
    f[2].write(s0(
        unsafe { f[2].assume_init() },
        unsafe { f[1].assume_init() } ^ b[1],
    ));
    f[0].write(s0(a[0], unsafe { f[1].assume_init() } ^ b[2]));
    f[3].write(s1(a[3], unsafe { f[2].assume_init() } ^ b[3]));

    u32::from_be_bytes(unsafe { transmute(f) })
}

fn s0(x1: u8, x2: u8) -> u8 {
    rot2(x1.wrapping_add(x2))
}

fn s1(x1: u8, x2: u8) -> u8 {
    rot2(x1.wrapping_add(x2).wrapping_add(1))
}

fn rot2(x: u8) -> u8 {
    let s = (x as u32) << 2;
    ((s & 0xff) | (s >> 8)) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt() {
        let key = 0x0123456789abcdef0123456789abcdefu128;
        let plaintext = 0u64;
        let cipher = FealNx::new(&key.to_be_bytes());
        let encrypted = cipher.encrypt(plaintext);
        assert_eq!(encrypted, 0x9c9b54973df685f8u64);
    }

    #[test]
    fn decrypt() {
        let key = 0x0123456789abcdef0123456789abcdefu128;
        let encrypted = 0x9c9b54973df685f8u64;
        let cipher = FealNx::new(&key.to_be_bytes());
        let decrypted = cipher.decrypt(encrypted);
        assert_eq!(decrypted, 0u64);
    }

    #[test]
    fn f() {
        assert_eq!(0x10041044, super::f(0x00ffff00, 0xffff));
    }

    #[test]
    fn fk() {
        assert_eq!(0x10041044, super::fk(0x00000000, 0x00000000));
    }

    #[test]
    fn invertibility() {
        const KEY_COUNT: usize = 1000;
        const BLOCK_COUNT: usize = 1000;

        use rand::{Rng, SeedableRng};

        let mut rng = rand::rngs::StdRng::seed_from_u64(0);
        for _ in 0..KEY_COUNT {
            let key: [u8; 16] = rng.gen();
            let cipher = FealNx::new(&key);
            for _ in 0..BLOCK_COUNT {
                let plaintext: u64 = rng.gen();
                let encrypted = cipher.encrypt(plaintext);
                let decrypted = cipher.decrypt(encrypted);
                assert_eq!(plaintext, decrypted);
            }
        }
    }
}
