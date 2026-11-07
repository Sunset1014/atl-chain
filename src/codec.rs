//! 序列化原语：小端整数、长度前缀字节串、32 字节哈希、hex、Base58Check。

/// 小端 u8
pub fn put_u8(b: &mut Vec<u8>, v: u8) { b.push(v) }
/// 小端 u16
pub fn put_u16(b: &mut Vec<u8>, v: u16) { b.extend_from_slice(&v.to_le_bytes()) }
/// 小端 u32
pub fn put_u32(b: &mut Vec<u8>, v: u32) { b.extend_from_slice(&v.to_le_bytes()) }
/// 小端 u64
pub fn put_u64(b: &mut Vec<u8>, v: u64) { b.extend_from_slice(&v.to_le_bytes()) }
/// 小端 i64
pub fn put_i64(b: &mut Vec<u8>, v: i64) { b.extend_from_slice(&v.to_le_bytes()) }
/// 原样追加
pub fn put_raw(b: &mut Vec<u8>, d: &[u8]) { b.extend_from_slice(d) }
/// u32 长度前缀 + 数据
pub fn put_bytes(b: &mut Vec<u8>, d: &[u8]) { put_u32(b, d.len() as u32); put_raw(b, d) }
/// 32 字节哈希原样追加
pub fn put_hash(b: &mut Vec<u8>, h: &[u8; 32]) { put_raw(b, h) }

/// 小写 hex
pub fn hex(d: &[u8]) -> String { d.iter().map(|b| format!("{b:02x}")).collect() }

/// hex -> bytes（奇数长度或非法字符返回 None）
pub fn unhex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()).collect()
}

const ALPHA: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Base58 编码
pub fn b58(d: &[u8]) -> String {
    let zeros = d.iter().take_while(|&&b| b == 0).count();
    let mut num = d.to_vec();
    let mut out = Vec::new();
    while !num.is_empty() {
        let mut rem = 0u32;
        let mut next = Vec::with_capacity(num.len());
        for &b in num.iter() {
            rem = rem * 256 + b as u32;
            let q = (rem / 58) as u8;
            if !(q == 0 && next.is_empty()) {
                next.push(q);
            }
            rem %= 58;
        }
        out.push(ALPHA[rem as usize]);
        num = next;
    }
    for _ in 0..zeros {
        out.push(ALPHA[0]);
    }
    out.reverse();
    String::from_utf8(out).unwrap()
}

/// Base58 解码
pub fn unb58(s: &str) -> Option<Vec<u8>> {
    let zeros = s.bytes().take_while(|&c| c == ALPHA[0]).count();
    let mut num: Vec<u8> = Vec::new();
    for c in s.bytes() {
        let mut carry = ALPHA.iter().position(|&x| x == c)? as u32;
        for x in num.iter_mut() {
            carry += (*x as u32) * 58;
            *x = carry as u8;
            carry >>= 8;
        }
        while carry > 0 {
            num.push(carry as u8);
            carry >>= 8;
        }
    }
    let mut out = vec![0u8; zeros];
    out.extend(num.iter().rev());
    Some(out)
}

/// Base58Check：base58(payload || sha256d(payload)[0..4])
pub fn b58check(d: &[u8]) -> String {
    let mut v = d.to_vec();
    v.extend_from_slice(&crate::hash::sha256d(d)[..4]);
    b58(&v)
}

/// Base58Check 解码，校验和错误返回 None
pub fn unb58check(s: &str) -> Option<Vec<u8>> {
    let v = unb58(s)?;
    if v.len() < 4 {
        return None;
    }
    let (d, c) = v.split_at(v.len() - 4);
    (crate::hash::sha256d(d)[..4] == *c).then(|| d.to_vec())
}

/// 只进不退的读取游标，越界/耗尽一律返回 None。
pub struct Rd<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Rd<'a> {
    /// 从字节切片建立游标
    pub fn new(b: &'a [u8]) -> Self { Rd { b, p: 0 } }
    /// 剩余未读字节数
    pub fn rest(&self) -> usize { self.b.len() - self.p }
    /// 读 u8
    pub fn u8(&mut self) -> Option<u8> { let v = *self.b.get(self.p)?; self.p += 1; Some(v) }
    /// 读小端 u16
    pub fn u16(&mut self) -> Option<u16> { Some(u16::from_le_bytes(self.raw(2)?.try_into().ok()?)) }
    /// 读小端 u32
    pub fn u32(&mut self) -> Option<u32> { Some(u32::from_le_bytes(self.raw(4)?.try_into().ok()?)) }
    /// 读小端 u64
    pub fn u64(&mut self) -> Option<u64> { Some(u64::from_le_bytes(self.raw(8)?.try_into().ok()?)) }
    /// 读小端 i64
    pub fn i64(&mut self) -> Option<i64> { Some(i64::from_le_bytes(self.raw(8)?.try_into().ok()?)) }
    /// 读固定 n 字节
    pub fn raw(&mut self, n: usize) -> Option<&'a [u8]> {
        let e = self.p.checked_add(n)?;
        if e > self.b.len() {
            return None;
        }
        let s = &self.b[self.p..e];
        self.p = e;
        Some(s)
    }
    /// 读 u32 长度前缀字节串
    pub fn bytes(&mut self) -> Option<&'a [u8]> { let n = self.u32()? as usize; self.raw(n) }
    /// 读 32 字节哈希
    pub fn hash(&mut self) -> Option<[u8; 32]> { self.raw(32)?.try_into().ok() }
}
