use aead::{consts::U16, KeyInit, KeySizeUser};
use aead::consts::U1;
use cipher::{BlockSizeUser, ParBlocksSizeUser};
use universal_hash::{UhfBackend, UhfClosure, UniversalHash};

use crate::gf::gf128_soft64::Element;

/// GHASH keys (16-bytes)
pub type Key = universal_hash::Key<GHash>;

/// GHASH blocks (16-bytes)
pub type Block = universal_hash::Block<GHash>;

/// GHASH tags (16-bytes)
pub type Tag = universal_hash::Block<GHash>;

pub(crate) struct GHash {
    s: Element,
    h: Element,
}

impl KeySizeUser for GHash {
    type KeySize = U16;
}

impl BlockSizeUser for GHash {
    type BlockSize = U16;
}

impl KeyInit for GHash {
    fn new(h: &Key) -> Self {
        Self::new_with_init_block(h, 0)
    }
}

impl GHash {
    pub(crate) fn new_with_init_block(h: &Key, s: u128) -> Self {
        Self {
            s: Element::from(s),
            h: Element::from(h),
        }
    }
    
    pub(crate) fn xor_s(&mut self, x: &Block) {
        self.s = self.s + Element::from(x);
    }
}

impl ParBlocksSizeUser for GHash { type ParBlocksSize = U1; }

impl UhfBackend for GHash {
    fn proc_block(&mut self, x: &Block) {
        println!("x: {:02X?}", Element::from(x));
        println!("s: {:02X?}", self.s);
        println!("h: {:02X?}", self.h);
        
        println!("s ^ x: {:02X?}", self.s + Element::from(x));
        println!("(s ^ x) * h: {:02X?}\n", (self.s + Element::from(x)) * self.h);
        self.s = (self.s + Element::from(x)) * self.h;
    }
}

impl UniversalHash for GHash {
    fn update_with_backend(&mut self, f: impl UhfClosure<BlockSize = Self::BlockSize>) {
        f.call(self)
    }

    /// Get GHASH output
    #[inline]
    fn finalize(self) -> Tag {
        (self.s * self.h).into()
    }
}

opaque_debug::implement!(GHash);
