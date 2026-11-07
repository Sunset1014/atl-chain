//! 钱包：密钥派生与转账（SPEC §5）。
use crate::chain::{Chain, Tx, TxIn, TxOut};
use crate::{codec, hash, secp};
use std::time::{SystemTime, UNIX_EPOCH};

const NM1: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xba, 0xae,
    0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x40,
];

/// 私钥 + 压缩公钥 + 地址哈希。
pub struct Key { pub sk: [u8; 32], pub pk: [u8; 33], pub addr: [u8; 20] }

impl Key {
    /// sk = sha256(b"ATL-wallet" || seed || idx.to_le_bytes())，落在 [1, n-1]。
    pub fn from_seed(seed: &[u8], idx: u32) -> Key {
        let buf = |extra: Option<u8>| {
            let mut b = b"ATL-wallet".to_vec();
            b.extend_from_slice(seed);
            b.extend_from_slice(&idx.to_le_bytes());
            if let Some(e) = extra { b.push(e) }
            b
        };
        let mut sk = hash::sha256(&buf(None));
        let mut n = 0u8;
        while sk == [0u8; 32] || sk.as_slice() > NM1.as_slice() {
            sk = hash::sha256(&buf(Some(n)));
            n = n.wrapping_add(1);
        }
        Key::of(sk)
    }
    /// 32 字节 hex 私钥。
    pub fn from_hex(s: &str) -> Option<Key> {
        let sk: [u8; 32] = codec::unhex(s)?.try_into().ok()?;
        Some(Key::of(sk))
    }
    /// 私钥的 hex。
    pub fn hex(&self) -> String { codec::hex(&self.sk) }
    fn of(sk: [u8; 32]) -> Key {
        let pk = secp::pubkey(&sk);
        Key { sk, pk, addr: secp::addr(&pk) }
    }
}

/// 随机种子：时间纳秒 + pid + 栈地址 + sha256（无 rand 依赖）。
pub fn new_seed() -> [u8; 32] {
    let mut b = Vec::with_capacity(32);
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    b.extend_from_slice(&nanos.to_le_bytes());
    b.extend_from_slice(&std::process::id().to_le_bytes());
    b.extend_from_slice(&(&b as *const Vec<u8> as usize).to_le_bytes());
    hash::sha256(&b)
}

/// 按 OutPoint 升序选 utxo，找零回 k.addr（change==0 省略），逐输入签名。
pub fn send(c: &Chain, k: &Key, to: [u8; 20], amount: u64, fee: u64, time: i64) -> Result<Tx, String> {
    if amount == 0 { return Err("amount must be positive".into()) }
    let need = amount.checked_add(fee).ok_or("amount overflow")?;
    let (mut picked, mut total) = (Vec::new(), 0u64);
    for (op, out) in c.utxos_of(&k.addr) {
        if total >= need { break }
        total += out.value;
        picked.push(op);
    }
    if total < need { return Err(format!("insufficient funds: have {total}, need {need}")) }
    let mut outs = vec![TxOut { value: amount, addr: to }];
    if total > need { outs.push(TxOut { value: total - need, addr: k.addr }) }
    let mut tx = Tx { time, ins: picked.iter().map(|p| TxIn { prev: *p, sig: Vec::new(), pk: Vec::new() }).collect(), outs };
    for i in 0..tx.ins.len() {
        tx.ins[i].sig = secp::sign(&k.sk, &tx.signing_hash(i)).to_vec();
        tx.ins[i].pk = k.pk.to_vec();
    }
    Ok(tx)
}
