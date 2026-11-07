//! secp256k1：域/标量算术、Jacobian 曲线运算、ECDSA 签名与验签、压缩公钥、地址摘要。
//! 全部基于 4×u64 小端肢体手写：域乘用 2^256 ≡ 0x1000003D1 折叠，求逆用二进制扩展 GCD。

use crate::hash::h160;

/// 256 位无符号整数（小端 64 位肢体）
pub type U = [u64; 4];
const ZERO: U = [0; 4];
/// 2^256 mod p
const C: u64 = 0x1_0000_03D1;

/// 域素数 p = 2^256 - 0x1000003D1
const P: U = [0xFFFF_FFFE_FFFF_FC2F, u64::MAX, u64::MAX, u64::MAX];
/// 曲线阶 n
const N: U = [0xBFD2_5E8C_D036_4141, 0xBAAE_DCE6_AF48_A03B, 0xFFFF_FFFF_FFFF_FFFE, u64::MAX];
/// 生成元 x
const GX: U = [0x59F2_815B_16F8_1798, 0x029B_FCDB_2DCE_28D9, 0x55A0_6295_CE87_0B07, 0x79BE_667E_F9DC_BBAC];
/// 生成元 y
const GY: U = [0x9C47_D08F_FB10_D4B8, 0xFD17_B448_A685_5419, 0x5DA4_FBFC_0E11_08A8, 0x483A_DA77_26A3_C465];

const fn one() -> U { [1, 0, 0, 0] }

fn from_be(b: [u8; 32]) -> U {
    let mut u = ZERO;
    for i in 0..4 {
        let mut w = [0u8; 8];
        w.copy_from_slice(&b[8 * i..8 * i + 8]);
        u[3 - i] = u64::from_be_bytes(w);
    }
    u
}

fn to_be(a: &U) -> [u8; 32] {
    let mut o = [0u8; 32];
    for i in 0..4 {
        o[8 * i..8 * i + 8].copy_from_slice(&a[3 - i].to_be_bytes());
    }
    o
}

/// a >= b
fn geq(a: &U, b: &U) -> bool {
    for i in (0..4).rev() {
        if a[i] != b[i] {
            return a[i] > b[i];
        }
    }
    true
}

/// 4 肢体减：(差, 借位)
fn sub(a: &U, b: &U) -> (U, bool) {
    let mut r = ZERO;
    let mut br = 0u128;
    for i in 0..4 {
        let t = (a[i] as u128).wrapping_sub(b[i] as u128).wrapping_sub(br);
        r[i] = t as u64;
        br = t >> 64 & 1;
    }
    (r, br != 0)
}

/// 4 肢体加：(和 5 肢体, 进位)
fn add(a: &U, b: &U) -> ([u64; 5], bool) {
    let mut r = [0u64; 5];
    let mut c = 0u128;
    for i in 0..4 {
        let t = a[i] as u128 + b[i] as u128 + c;
        r[i] = t as u64;
        c = t >> 64;
    }
    r[4] = c as u64;
    (r, c != 0)
}

fn geq5(a: &[u64; 5], b: &U) -> bool {
    if a[4] != 0 {
        return true;
    }
    geq(&[a[0], a[1], a[2], a[3]], b)
}

fn sub5(a: &[u64; 5], b: &U) -> [u64; 5] {
    let mut r = [0u64; 5];
    let mut br = 0u128;
    for i in 0..5 {
        let bb = if i < 4 { b[i] as u128 } else { 0 };
        let t = (a[i] as u128).wrapping_sub(bb).wrapping_sub(br);
        r[i] = t as u64;
        br = t >> 64 & 1;
    }
    r
}

fn shr(a: &U, k: u32) -> U {
    if k == 0 {
        return *a;
    }
    let mut r = ZERO;
    let mut c = 0u64;
    for i in (0..4).rev() {
        r[i] = (a[i] >> k) | (c << (64 - k));
        c = a[i] & ((1u64 << k) - 1);
    }
    r
}

/// 5 肢体右移（k ∈ 1..64）
fn shr5(a: &[u64; 5], k: u32) -> U {
    if k == 0 {
        return [a[0], a[1], a[2], a[3]];
    }
    let mut r = ZERO;
    let mut c = 0u64;
    for i in (0..5).rev() {
        if i < 4 {
            r[i] = (a[i] >> k) | (c << (64 - k));
        }
        c = a[i] & ((1u64 << k) - 1);
    }
    r
}

fn bit(a: &U, i: usize) -> bool { a[i / 64] >> (i % 64) & 1 == 1 }

/// 把 5 肢体值用 2^256 ≡ C (mod p) 折回 [0, p)
fn fold(t: &mut [u64; 5]) -> U {
    while t[4] != 0 {
        let h = t[4];
        t[4] = 0;
        let mut add = (h as u128) * (C as u128);
        let mut c = 0u128;
        for i in 0..4 {
            let x = t[i] as u128 + (add as u64) as u128 + c;
            add >>= 64;
            t[i] = x as u64;
            c = x >> 64;
        }
        t[4] = c as u64;
    }
    let r = [t[0], t[1], t[2], t[3]];
    if geq(&r, &P) { sub(&r, &P).0 } else { r }
}

pub(crate) fn f_add(a: &U, b: &U) -> U {
    let (mut s, _) = add(a, b);
    fold(&mut s)
}

/// 2^256 - n
const CN: U = [0x402D_A173_2FC9_BEBF, 0x4551_2319_50B7_5FC4, 1, 0];
/// 2^256 - p
const CP: U = [C, 0, 0, 0];

pub(crate) fn f_sub(a: &U, b: &U) -> U {
    let (r, br) = sub(a, b);
    // 借位时 r = a - b + 2^256，目标 a - b + p = r - (2^256 - p) = r - CP
    if br { sub(&r, &CP).0 } else { r }
}

/// 域乘：4×4 学校乘法 + 高位折叠约简
pub(crate) fn f_mul(a: &U, b: &U) -> U {
    let mut w = [0u64; 8];
    for i in 0..4 {
        let mut c = 0u128;
        for j in 0..4 {
            let t = w[i + j] as u128 + (a[i] as u128) * (b[j] as u128) + c;
            w[i + j] = t as u64;
            c = t >> 64;
        }
        let mut k = i + 4;
        while c > 0 && k < 8 {
            let t = w[k] as u128 + c;
            w[k] = t as u64;
            c = t >> 64;
            k += 1;
        }
    }
    // t = H*C + L，其中 H = w[4..8]、L = w[0..4]
    let mut t = [0u64; 5];
    let mut c = 0u128;
    for i in 0..4 {
        let x = (w[4 + i] as u128) * (C as u128) + c;
        t[i] = x as u64;
        c = x >> 64;
    }
    t[4] = c as u64;
    let mut c = 0u128;
    for i in 0..4 {
        let x = t[i] as u128 + w[i] as u128 + c;
        t[i] = x as u64;
        c = x >> 64;
    }
    t[4] = t[4].wrapping_add(c as u64);
    fold(&mut t)
}

pub(crate) fn f_mul_small(a: &U, k: u64) -> U { f_mul(a, &[k, 0, 0, 0]) }

/// 模幂（平方-乘，指数 MSB→LSB）
pub(crate) fn f_pow(a: &U, e: &U) -> U {
    let mut r = one();
    let mut started = false;
    for i in (0..256).rev() {
        if started {
            r = f_mul(&r, &r);
        }
        if bit(e, i) {
            r = if started { f_mul(&r, a) } else { *a };
            started = true;
        }
    }
    r
}

/// (a + m) / 2，要求 a < m
fn half_mod(a: &U, m: &U) -> U {
    if a[0] & 1 == 0 { shr(a, 1) } else { shr5(&add(a, m).0, 1) }
}

/// 模逆（二进制扩展欧几里得）。m 为奇数素数，0 < a < m。
fn inv_mod(a: &U, m: &U) -> U {
    if *a == ZERO { return ZERO }
    let mut u = *a;
    let mut v = *m;
    let mut x1 = one();
    let mut x2 = ZERO;
    while u != one() && v != one() {
        if u == v { return if u == one() { x1 } else { ZERO } }
        while u[0] & 1 == 0 {
            u = shr(&u, 1);
            x1 = half_mod(&x1, m);
        }
        while v[0] & 1 == 0 {
            v = shr(&v, 1);
            x2 = half_mod(&x2, m);
        }
        if geq(&u, &v) {
            u = sub(&u, &v).0;
            x1 = n_sub_mod(&x1, &x2, m);
        } else {
            v = sub(&v, &u).0;
            x2 = n_sub_mod(&x2, &x1, m);
        }
    }
    if u == one() { x1 } else { x2 }
}

/// a - b mod m（a,b < m，m 为奇数）
fn n_sub_mod(a: &U, b: &U, m: &U) -> U {
    let (r, br) = sub(a, b);
    if !br { return r }
    let (s, _) = add(&r, m);
    [s[0], s[1], s[2], s[3]]
}

/// 域逆元
pub(crate) fn f_inv(a: &U) -> U { inv_mod(a, &P) }

fn n_add(a: &U, b: &U) -> U {
    let (s, _) = add(a, b);
    let r = [s[0], s[1], s[2], s[3]];
    if s[4] != 0 {
        // 有进位时 r = a+b-2^256，补上 2^256-n 即得 a+b-n
        let (t, _) = add(&r, &CN);
        [t[0], t[1], t[2], t[3]]
    } else if geq(&r, &N) {
        sub(&r, &N).0
    } else {
        r
    }
}

fn n_sub(a: &U, b: &U) -> U {
    let (r, br) = sub(a, b);
    if br { sub(&r, &CN).0 } else { r }
}

/// 512 位值对 n 取模：逐位长除法
fn red_n(w: &[u64; 8]) -> U {
    let mut r = [0u64; 5];
    for i in (0..512).rev() {
        let mut c = w[i / 64] >> (i % 64) & 1;
        for j in 0..5 {
            let x = (r[j] as u128) << 1 | c as u128;
            r[j] = x as u64;
            c = (x >> 64) as u64;
        }
        if geq5(&r, &N) {
            r = sub5(&r, &N);
        }
    }
    [r[0], r[1], r[2], r[3]]
}

/// 模 n 乘：学校乘法 + 长除法约简
pub(crate) fn n_mul(a: &U, b: &U) -> U {
    let mut w = [0u64; 8];
    for i in 0..4 {
        let mut c = 0u128;
        for j in 0..4 {
            let t = w[i + j] as u128 + (a[i] as u128) * (b[j] as u128) + c;
            w[i + j] = t as u64;
            c = t >> 64;
        }
        let mut k = i + 4;
        while c > 0 && k < 8 {
            let t = w[k] as u128 + c;
            w[k] = t as u64;
            c = t >> 64;
            k += 1;
        }
    }
    red_n(&w)
}

fn n_inv(a: &U) -> U { inv_mod(a, &N) }

/// 任意 256 位值规约到 [0, n)
fn mod_n(a: &U) -> U {
    if geq(a, &N) { sub(a, &N).0 } else { *a }
}

// ---------------- 曲线运算（Jacobian，a = 0） ----------------

/// Jacobian 点：x = X/Z²，y = Y/Z³；Z = 0 为无穷远点
#[derive(Clone, Copy, Debug)]
pub struct Pt { pub x: U, pub y: U, pub z: U }

fn inf() -> Pt { Pt { x: ZERO, y: ZERO, z: ZERO } }
fn is_inf(p: &Pt) -> bool { p.z == ZERO }
fn base() -> Pt { Pt { x: GX, y: GY, z: one() } }

fn dbl(p: &Pt) -> Pt {
    if is_inf(p) || p.y == ZERO {
        return inf();
    }
    let a = f_mul(&p.x, &p.x);
    let b = f_mul(&p.y, &p.y);
    let c = f_mul(&b, &b);
    let t = f_add(&p.x, &b);
    let d = f_mul_small(&f_sub(&f_sub(&f_mul(&t, &t), &a), &c), 2);
    let e = f_add(&a, &f_mul_small(&a, 2));
    let x3 = f_sub(&f_mul(&e, &e), &f_mul_small(&d, 2));
    let y3 = f_sub(&f_mul(&e, &f_sub(&d, &x3)), &f_mul_small(&c, 8));
    let z3 = f_mul_small(&f_mul(&p.y, &p.z), 2);
    Pt { x: x3, y: y3, z: z3 }
}

fn padd(p: &Pt, q: &Pt) -> Pt {
    if is_inf(p) { return *q; }
    if is_inf(q) { return *p; }
    let z1z1 = f_mul(&p.z, &p.z);
    let z2z2 = f_mul(&q.z, &q.z);
    let u1 = f_mul(&p.x, &z2z2);
    let u2 = f_mul(&q.x, &z1z1);
    let s1 = f_mul(&f_mul(&p.y, &q.z), &z2z2);
    let s2 = f_mul(&f_mul(&q.y, &p.z), &z1z1);
    if u1 == u2 {
        return if s1 == s2 { dbl(p) } else { inf() };
    }
    let h = f_sub(&u2, &u1);
    let h2 = f_mul_small(&h, 2);
    let i = f_mul(&h2, &h2);
    let j = f_mul(&h, &i);
    let r = f_mul_small(&f_sub(&s2, &s1), 2);
    let v = f_mul(&u1, &i);
    let x3 = f_sub(&f_sub(&f_mul(&r, &r), &j), &f_mul_small(&v, 2));
    let y3 = f_sub(&f_mul(&r, &f_sub(&v, &x3)), &f_mul_small(&f_mul(&s1, &j), 2));
    let zz = f_add(&p.z, &q.z);
    let z3 = f_mul(&f_sub(&f_sub(&f_mul(&zz, &zz), &z1z1), &z2z2), &h);
    Pt { x: x3, y: y3, z: z3 }
}

/// 标量乘法（双倍-加法，MSB→LSB）
pub fn mul(p: &Pt, k: &U) -> Pt {
    let mut r = inf();
    let mut started = false;
    for i in (0..256).rev() {
        if started {
            r = dbl(&r);
        }
        if bit(k, i) {
            r = if started { padd(&r, p) } else { *p };
            started = true;
        }
    }
    r
}

/// 仿射坐标
fn affine(p: &Pt) -> Option<(U, U)> {
    if is_inf(p) {
        return None;
    }
    let zi = f_inv(&p.z);
    let zi2 = f_mul(&zi, &zi);
    Some((f_mul(&p.x, &zi2), f_mul(&p.y, &f_mul(&zi2, &zi))))
}

/// 解压 33 字节压缩公钥
pub fn decode(pk: &[u8; 33]) -> Option<Pt> {
    if pk[0] != 2 && pk[0] != 3 {
        return None;
    }
    let x = from_be(pk[1..].try_into().ok()?);
    if geq(&x, &P) {
        return None;
    }
    let y2 = f_add(&f_mul(&f_mul(&x, &x), &x), &[7, 0, 0, 0]);
    // 指数 (p+1)/4 = 2^254 - 0x400000F4
    let mut e = P;
    e[0] = e[0].wrapping_add(1);
    let mut c = 0u64;
    for i in (0..4).rev() {
        let lo = e[i] & 3;
        e[i] = (e[i] >> 2) | (c << 62);
        c = lo;
    }
    let mut y = f_pow(&y2, &e);
    if f_mul(&y, &y) != y2 {
        return None;
    }
    if (y[0] & 1 == 1) != (pk[0] == 3) {
        y = f_sub(&P, &y);
    }
    Some(Pt { x, y, z: one() })
}

/// 私钥 -> 33 字节压缩公钥
pub fn pubkey(sk: &[u8; 32]) -> [u8; 33] {
    let q = mul(&base(), &mod_n(&from_be(*sk)));
    let mut o = [0u8; 33];
    if let Some((x, y)) = affine(&q) {
        o[0] = if y[0] & 1 == 1 { 3 } else { 2 };
        o[1..].copy_from_slice(&to_be(&x));
    }
    o
}

/// 地址摘要 = h160(压缩公钥)
pub fn addr(pk: &[u8; 33]) -> [u8; 20] { h160(pk) }

/// ECDSA 签名（确定性 nonce，r||s，s 已做 low-s 规范化）
pub fn sign(sk: &[u8; 32], msg: &[u8; 32]) -> [u8; 64] {
    let d = mod_n(&from_be(*sk));
    let z = mod_n(&from_be(*msg));
    let mut seed = Vec::with_capacity(37);
    seed.extend_from_slice(b"ATL-k");
    seed.extend_from_slice(sk);
    seed.extend_from_slice(msg);
    let mut k = mod_n(&from_be(crate::hash::sha256(&seed)));
    if k == ZERO {
        k = one();
    }
    let r = match affine(&mul(&base(), &k)) {
        Some((x, _)) => mod_n(&x),
        None => return [0; 64],
    };
    if r == ZERO {
        return [0; 64];
    }
    let s = n_mul(&n_add(&z, &n_mul(&r, &d)), &n_inv(&k));
    if s == ZERO {
        return [0; 64];
    }
    let s = if geq(&s, &shr(&N, 1)) { n_sub(&N, &s) } else { s };
    let mut o = [0u8; 64];
    o[..32].copy_from_slice(&to_be(&r));
    o[32..].copy_from_slice(&to_be(&s));
    o
}

/// 验签
pub fn verify(pk: &[u8; 33], msg: &[u8; 32], sig: &[u8; 64]) -> bool {
    let q = match decode(pk) {
        Some(q) => q,
        None => return false,
    };
    let r = from_be(sig[..32].try_into().unwrap());
    let s = from_be(sig[32..].try_into().unwrap());
    if r == ZERO || s == ZERO || geq(&r, &N) || geq(&s, &N) {
        return false;
    }
    let w = n_inv(&s);
    let u1 = n_mul(&mod_n(&from_be(*msg)), &w);
    let u2 = n_mul(&r, &w);
    let pt = padd(&mul(&base(), &u1), &mul(&q, &u2));
    match affine(&pt) {
        Some((x, _)) => mod_n(&x) == r,
        None => false,
    }
}

#[cfg(test)]
mod dbg {
    use super::*;
    fn u(v: u64) -> U { [v, 0, 0, 0] }

    #[test]
    fn t_field() {
        assert_eq!(f_mul(&u(3), &u(7)), u(21));
        assert_eq!(f_add(&u(1), &f_sub(&P, &u(1))), u(0));
        assert_eq!(f_sub(&u(0), &u(1)), f_sub(&P, &u(1)));
        assert_eq!(f_mul(&u(123456789), &f_inv(&u(123456789))), u(1));
        assert_eq!(f_mul(&GX, &f_inv(&GX)), u(1));
        // 分配律：2*(GX+GY) == 2*GX + 2*GY
        assert_eq!(f_mul(&u(2), &f_add(&GX, &GY)), f_add(&f_mul(&u(2), &GX), &f_mul(&u(2), &GY)));
    }

    #[test]
    fn t_scalar() {
        assert_eq!(n_mul(&u(123456789), &u(1)), u(123456789));
        assert_eq!(n_mul(&u(123456789), &u(2)), n_add(&u(123456789), &u(123456789)));
        assert_eq!(n_mul(&u(123456789), &n_inv(&u(123456789))), u(1));
        assert_eq!(n_add(&n_sub(&N, &u(1)), &u(1)), u(0));
        let a = GX; // 任意 < n 的值
        assert_eq!(n_mul(&a, &n_inv(&a)), u(1));
        assert_eq!(n_mul(&GX, &GY), n_mul(&GY, &GX));
    }

    #[test]
    fn t_curve() {
        let g = base();
        let two = mul(&g, &u(2));
        let g2 = padd(&g, &g);
        assert!(two.x == g2.x && two.y == g2.y && two.z == g2.z);
        let (x, y) = affine(&two).unwrap();
        assert_eq!(to_be(&x), *b"\xc6\x04\x7f\x94\x41\xed\x7d\x6d\x30\x45\x40\x6e\x95\xc0\x7c\xd8\x5c\x77\x8e\x4b\x8c\xef\x3c\xa7\xab\xac\x09\xb9\x5c\x70\x9e\xe5");
        assert_eq!(to_be(&y), *b"\x1a\xe1\x68\xfe\xa6\x3d\xc3\x39\xa3\xc5\x84\x19\x46\x6c\xea\xee\xf7\xf6\x32\x65\x32\x66\xd0\xe1\x23\x64\x31\xa9\x50\xcf\xe5\x2a");
        // 3G + G == 4G（加法结合性）
        let three = mul(&g, &u(3));
        let four = mul(&g, &u(4));
        let sum = padd(&three, &g);
        let (a, b) = affine(&sum).unwrap();
        let (c, d) = affine(&four).unwrap();
        assert!(a == c && b == d);
    }

    #[test]
    fn t_decode() {
        let mut sk1 = [0u8; 32];
        sk1[31] = 1;
        let q = decode(&pubkey(&sk1)).expect("decode");
        let (x, y) = affine(&q).unwrap();
        assert_eq!(x, GX);
        assert_eq!(y, GY);
        for k in [2u64, 3, 7, 12345] {
            let p = affine(&mul(&base(), &u(k))).unwrap();
            assert_eq!(f_mul(&p.1, &p.1), f_add(&f_mul(&f_mul(&p.0, &p.0), &p.0), &u(7)), "k={k}");
        }
    }
}
