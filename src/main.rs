
use belt_block::belt_block_raw;
use belt_block::cipher::Key;
use ghash::GHash;
use ghash::universal_hash::{KeyInit, UniversalHash};
use hex_literal::hex;

const T: u128 = 0xB194BAC80A08F53B366D008E584A5DE4;

/// Helper function for transforming BelT keys and blocks from a byte array
/// to an array of `u32`s.
///
/// # Panics
/// If length of `src` is not equal to `4 * N`.
// #[inline(always)]
pub(crate) fn to_u32<const N: usize>(src: &[u8]) -> [u32; N] {
    assert_eq!(src.len(), 4 * N);
    let mut res = [0u32; N];
    res.iter_mut()
        .zip(src.chunks_exact(4))
        .for_each(|(dst, src)| *dst = u32::from_le_bytes(src.try_into().unwrap()));
    res
}


/// Helper function for transforming BelT keys and blocks from a array of `u32`s
/// to a byte array.
///
/// # Panics
/// If length of `src` is not equal to `4 * N`.
// #[inline(always)]
pub(crate) fn from_u32<const N: usize>(src: &[u32]) -> [u8; N] {
    assert_eq!(N, 4 * src.len());
    let mut res = [0u8; N];
    src.iter()
        .zip(res.chunks_exact_mut(4))
        .for_each(|(src, dst)| dst.copy_from_slice(&src.to_le_bytes()));
    res
}


fn main() {
    let mut i = hex!("8504FA9D 1BB6C7AC 252E72C2 02FDCE0D 5BE3D612 17B96181 FE6786AD 716B890B");
    i[..16].iter_mut().zip(T.to_be_bytes().iter()).for_each(|(i, j)| {
        *i ^= j;
    });
    println!("{:02X?}", i);
    i.chunks_mut(16).for_each(|chunk| {
        chunk.reverse();
    });

    let k = hex!("E9DEE72C 8F0C0FA6 2DDB49F4 6F739647 06075316 ED247A37 39CBA383 03A98BF6");
    let s = hex!("BE329713 43FC9A48 A02A885F 194B09A1");
    let mut x = hex!("B194BAC8 0A08F53B 366D008E 584A5DE4");

    let y = hex!("52C9AF96 FF50F644 35FC43DE F56BD797");
    let t = hex!("3B2E0AEB 2B91854B");


    // Выполняем шаги алгоритма belt-dwp вплоть до 4
    let _s = to_u32::<4>(&s);
    let _k = to_u32::<8>(&k);
    // 2.1. 𝑠 ← belt-block(𝑆, 𝐾);
    let s = belt_block_raw(_s, &_k);
    // 2.2. 𝑟 ← belt-block(𝑠, 𝐾);
    let r = belt_block_raw(s, &_k);
    let mut r = from_u32::<16>(&r);
    // r.reverse();
    let ghash_key = Key::<GHash>::from(r);
    println!("ghash key: {:02X?}", ghash_key);

    let mut ghash = GHash::new(&ghash_key);

    ghash.update_padded(&i);

    // Если смотреть по результатам шагов выполнения, то вот что получается (soft64.rs)
    // ghash_key: [22, 48, 17, 83, 87, 61, A9, D6, E3, EC, 96, 89, 11, 0F, B0, F3]
    // s ^ x: U64x2(9732BE1155409034, E993B75A4C724313)
    // (s ^ x) * h: U64x2(C0B4513066C11059, 25CB56B7D6A0EB8)
    //
    // s ^ x: U64x2(41D5E8277417F302, 9D5DE1AD0EC6946)
    // (s ^ x) * h: U64x2(58FD16E630E85DCA, 186890A9D02C7B51)
    //
    // [18, 68, 90, A9, D0, 2C, 7B, 51, 58, FD, 16, E6, 30, E8, 5D, CA]
    // Также прикладываю результат в SageMath, который тоже не похож на проверочный пример.
    println!("tag: {:02X?}", ghash.finalize());
}
