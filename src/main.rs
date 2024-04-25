use aead::{
    AeadCore,
    AeadInPlace, consts::{U0, U16, U32, U8}, Key, KeyInit, KeySizeUser, Nonce, Tag,
};
use belt_block::{belt_block_raw, BeltBlock};
use belt_ctr::BeltCtr;
use cipher::{Block, Iv, KeyIvInit, StreamCipher};
use hex_literal::hex;
use universal_hash::UniversalHash;

use crate::{
    ghash::GHash,
    utils::{from_u32, to_u32},
};

mod gf;
mod ghash;
mod utils;

const T: u128 = 0xB194BAC80A08F53B366D008E584A5DE4;

pub struct BeltDwp {
    key: Key<BeltBlock>,
}

impl KeySizeUser for BeltDwp {
    type KeySize = U32;
}

impl AeadInPlace for BeltDwp {
    fn encrypt_in_place_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> aead::Result<Tag<Self>> {
        let plain_cnt = associated_data.len() as u64 * 8;
        let sec_cnt = buffer.len() as u64 * 8;

        let _s = to_u32::<4>(nonce);
        let _k = to_u32::<8>(&self.key);
        // 2.1. 𝑠 ← belt-block(𝑆, 𝐾);
        let s = belt_block_raw(_s, &_k);
        // 2.2. 𝑟 ← belt-block(𝑠, 𝐾);
        let r = from_u32::<16>(&belt_block_raw(s, &_k));

        let iv = Iv::<BeltCtr>::from_slice(nonce);
        let mut cipher: BeltCtr = BeltCtr::new(&self.key, iv);

        let mut ghash = GHash::new_with_init_block(Key::<GHash>::from_slice(&r), T.swap_bytes());

        // 3. For 𝑖 = 1, 2, . . . , 𝑚 do:
        //  3.1 𝑡 ← 𝑡 ⊕ (𝐼𝑖 ‖ 0^{128−|𝐼𝑖|})
        //  3.2 𝑡 ← 𝑡 * 𝑟.
        ghash.update_padded(associated_data);

        // 4. For 𝑖 = 1, 2, . . . , 𝑛 do:
        //  4.1 𝑠 ← 𝑠 ⊞ ⟨1⟩_128
        //  4.2 𝑌𝑖 ← 𝑋𝑖 ⊕ Lo(belt-block(𝑠, 𝐾), |𝑋𝑖|)
        //  4.3 𝑡 ← 𝑡 ⊕ (𝑌𝑖 ‖ 0^{128−|𝑌𝑖|})
        //  4.4 𝑡 ← 𝑡 * 𝑟.
        buffer.chunks_mut(16).for_each(|block| {
            cipher.apply_keystream(block);
            ghash.update_padded(block);
        });

        let mut sizes_block: Block::<GHash> = Default::default();

        sizes_block[..8].copy_from_slice(&plain_cnt.to_le_bytes());
        sizes_block[8..].copy_from_slice(&sec_cnt.to_le_bytes());

        // 5. 𝑡 ← 𝑡 ⊕ (⟨|𝐼|⟩_64 ‖ ⟨|𝑋|⟩_64)
        ghash.xor_s(&sizes_block);

        // 6. 𝑡 ← belt-block(𝑡 * 𝑟, 𝐾).
        let tag = ghash.finalize();

        let hmac = from_u32::<16>(&belt_block_raw(to_u32::<4>(&tag), &_k));

        Ok(*Tag::<BeltDwp>::from_slice(&hmac[..8]))
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag<Self>,
    ) -> aead::Result<()> {
        let plain_cnt = associated_data.len() as u64 * 8;
        let sec_cnt = buffer.len() as u64 * 8;

        let _s = to_u32::<4>(nonce);
        let _k = to_u32::<8>(&self.key);
        // 2.1. 𝑠 ← belt-block(𝑆, 𝐾);
        let s = belt_block_raw(_s, &_k);
        // 2.2. 𝑟 ← belt-block(𝑠, 𝐾);
        let r = from_u32::<16>(&belt_block_raw(s, &_k));

        let iv = Iv::<BeltCtr>::from_slice(nonce);
        let mut cipher: BeltCtr = BeltCtr::new(&self.key, iv);

        let mut ghash = GHash::new_with_init_block(Key::<GHash>::from_slice(&r), T.swap_bytes());

        // 3. For 𝑖 = 1, 2, . . . , 𝑚 do:
        //  3.1 𝑡 ← 𝑡 ⊕ (𝐼𝑖 ‖ 0^{128−|𝐼𝑖|})
        //  3.2 𝑡 ← 𝑡 * 𝑟.
        ghash.update_padded(associated_data);

        // 4. For 𝑖 = 1, 2, . . . , 𝑛 do:
        //  4.1 𝑡 ← 𝑡 ⊕ (𝑌𝑖 ‖ 0^{128−|𝑌𝑖|})
        //  4.2 𝑡 ← 𝑡 * 𝑟.
        ghash.update_padded(buffer);

        let mut sizes_block: Block::<GHash> = Default::default();

        sizes_block[..8].copy_from_slice(&plain_cnt.to_le_bytes());
        sizes_block[8..].copy_from_slice(&sec_cnt.to_le_bytes());

        // 5. 𝑡 ← 𝑡 ⊕ (⟨|𝐼|⟩_64 ‖ ⟨|𝑋|⟩_64)
        ghash.xor_s(&sizes_block);

        // 6. 𝑡 ← belt-block(𝑡 * 𝑟, 𝐾).
        let tag_exact = ghash.finalize();

        let hmac = from_u32::<16>(&belt_block_raw(to_u32::<4>(&tag_exact), &_k));
        // 7. If 𝑇 != Lo(𝑡, 64), return ⊥
        if hmac[..8] != tag[..] {
            return Err(aead::Error);
        }
        
        buffer.chunks_mut(16).for_each(|block| {
            cipher.apply_keystream(block);
        }); 

        Ok(())
    }
}

impl KeyInit for BeltDwp {
    fn new(key: &Key<Self>) -> Self {
        Self {
            key: *key,
        }
    }
}

impl AeadCore for BeltDwp {
    type NonceSize = U16;
    type TagSize = U8;
    type CiphertextOverhead = U0;
}

fn main() {
    let i = hex!("8504FA9D1BB6C7AC252E72C202FDCE0D 5BE3D612 17B96181 FE6786AD 716B890B");
    let k = hex!("E9DEE72C 8F0C0FA6 2DDB49F4 6F739647 06075316 ED247A37 39CBA383 03A98BF6");
    let s = hex!("BE329713 43FC9A48 A02A885F 194B09A1");
    let _x = hex!("B194BAC8 0A08F53B 366D008E 584A5DE4");
    
    let mut x = hex!("B194BAC8 0A08F53B 366D008E 584A5DE4");

    let y = hex!("52C9AF96 FF50F644 35FC43DE F56BD797");
    let t = hex!("3B2E0AEB 2B91854B");

    let beltdwp = BeltDwp::new_from_slice(&k).unwrap();
    let tag = beltdwp.encrypt_in_place_detached(&s.into(), &i, &mut x);
    
    assert_eq!(t, *tag.unwrap());
    assert_eq!(y, x);
    
    beltdwp.decrypt_in_place_detached(&s.into(), &i, &mut x, &tag.unwrap()).unwrap();
    assert_eq!(x, _x);
}
