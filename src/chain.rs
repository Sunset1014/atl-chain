//! 链、交易、共识与内存池（SPEC §4）。
use crate::codec::{self, Rd};
use crate::{hash, secp};
use std::collections::{HashMap, HashSet};

pub const COIN: u64 = 100_000_000;
pub const SPACING: i64 = 60;
pub const HALVING: u64 = 210_000;
pub const RETARGET: u64 = 2016;
pub const MAX_FRAME: usize = 4 << 20;
pub const GENESIS_TIME: i64 = 1_700_000_000;
pub const GENESIS_ADDR: [u8; 20] = [0; 20];

/// UTXO 引用：交易 id + 输出下标。
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug, Default)]
pub struct OutPoint { pub txid: [u8; 32], pub idx: u32 }
/// 交易输入：引用 + 签名 + 压缩公钥。
#[derive(Clone, Debug)]
pub struct TxIn { pub prev: OutPoint, pub sig: Vec<u8>, pub pk: Vec<u8> }
/// 交易输出：金额 + 地址哈希。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxOut { pub value: u64, pub addr: [u8; 20] }
/// 交易。
#[derive(Clone, Debug)]
pub struct Tx { pub time: i64, pub ins: Vec<TxIn>, pub outs: Vec<TxOut> }
/// 区块。
#[derive(Clone, Debug)]
pub struct Block { pub prev: [u8; 32], pub time: i64, pub bits: u32, pub nonce: u32, pub txs: Vec<Tx> }

impl Tx {
    /// 完整编码（含 sig/pk）。
    pub fn enc(&self) -> Vec<u8> { self.enc_with(true) }
    /// 签名哈希用的编码：所有 sig/pk 编码为空 bytes。
    fn enc_nosig(&self) -> Vec<u8> { self.enc_with(false) }
    fn enc_with(&self, sig: bool) -> Vec<u8> {
        let mut b = Vec::new();
        codec::put_u32(&mut b, self.ins.len() as u32);
        for i in &self.ins {
            codec::put_hash(&mut b, &i.prev.txid);
            codec::put_u32(&mut b, i.prev.idx);
            let (s, p): (&[u8], &[u8]) = if sig { (&i.sig, &i.pk) } else { (&[], &[]) };
            codec::put_bytes(&mut b, s);
            codec::put_bytes(&mut b, p);
        }
        codec::put_u32(&mut b, self.outs.len() as u32);
        for o in &self.outs { codec::put_u64(&mut b, o.value); codec::put_raw(&mut b, &o.addr); }
        codec::put_i64(&mut b, self.time);
        b
    }
    /// 反序列化（按 §4.2 的字段顺序）。
    pub fn dec(r: &mut Rd) -> Option<Tx> {
        let n = r.u32()? as usize;
        let mut ins = Vec::with_capacity(n.min(4096));
        for _ in 0..n {
            let prev = OutPoint { txid: r.hash()?, idx: r.u32()? };
            ins.push(TxIn { prev, sig: r.bytes()?.to_vec(), pk: r.bytes()?.to_vec() });
        }
        let m = r.u32()? as usize;
        let mut outs = Vec::with_capacity(m.min(4096));
        for _ in 0..m {
            let value = r.u64()?;
            let addr: [u8; 20] = r.raw(20)?.try_into().ok()?;
            outs.push(TxOut { value, addr });
        }
        let time = r.i64()?;
        Some(Tx { time, ins, outs })
    }
    /// txid = sha256d(enc())。
    pub fn id(&self) -> [u8; 32] { hash::sha256d(&self.enc()) }
    /// coinbase：1 个输入，prev = ([0;32], 0xffff_ffff)。
    pub fn is_coinbase(&self) -> bool {
        self.ins.len() == 1 && self.ins[0].prev.txid == [0; 32] && self.ins[0].prev.idx == u32::MAX
    }
    /// sha256d(enc_nosig() || i as u32 LE)。
    pub fn signing_hash(&self, i: usize) -> [u8; 32] {
        let mut b = self.enc_nosig();
        codec::put_u32(&mut b, i as u32);
        hash::sha256d(&b)
    }
}

impl Block {
    /// 32 prev, i64 time, u32 bits, u32 nonce（48 字节）。
    pub fn header(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(48);
        codec::put_hash(&mut b, &self.prev);
        codec::put_i64(&mut b, self.time);
        codec::put_u32(&mut b, self.bits);
        codec::put_u32(&mut b, self.nonce);
        b
    }
    /// header || u32 n_tx || bytes(tx.enc())...
    pub fn enc(&self) -> Vec<u8> {
        let mut b = self.header();
        codec::put_u32(&mut b, self.txs.len() as u32);
        for t in &self.txs { codec::put_bytes(&mut b, &t.enc()); }
        b
    }
    /// 反序列化。
    pub fn dec(r: &mut Rd) -> Option<Block> {
        let prev = r.hash()?;
        let time = r.i64()?;
        let bits = r.u32()?;
        let nonce = r.u32()?;
        let n = r.u32()? as usize;
        let mut txs = Vec::with_capacity(n.min(4096));
        for _ in 0..n { txs.push(Tx::dec(&mut Rd::new(r.bytes()?))?); }
        Some(Block { prev, time, bits, nonce, txs })
    }
    pub fn hash(&self) -> [u8; 32] { hash::sha256d(&self.header()) }
    pub fn merkle(&self) -> [u8; 32] { hash::merkle(&self.txs.iter().map(|t| t.id()).collect::<Vec<_>>()) }
}

/// 紧凑 bits -> 32 字节大端目标值。
pub fn target(bits: u32) -> [u8; 32] {
    let (exp, mant) = (bits >> 24, bits & 0xff_ffff);
    let mut t = [0u8; 32];
    if mant == 0 { return t }
    let m = [(mant >> 16) as u8, (mant >> 8) as u8, mant as u8];
    if exp >= 3 {
        let sh = (exp - 3) as usize;
        for (k, byte) in m.iter().enumerate() {
            match sh + 2 - k {
                pos if pos < 32 => t[31 - pos] = *byte,
                _ if *byte != 0 => return [0xff; 32],
                _ => {}
            }
        }
    } else {
        let sh = 8 * (3 - exp) as usize;
        let v = if sh >= 24 { 0 } else { mant >> sh };
        for (k, byte) in [(v >> 16) as u8, (v >> 8) as u8, v as u8].iter().enumerate() { t[29 + k] = *byte }
    }
    t
}
/// 哈希（大端）<= target。
pub fn pow_ok(h: &[u8; 32], bits: u32) -> bool { *h <= target(bits) }
/// 50*COIN >> (height/HALVING)，位移 >= 64 记 0。
pub fn subsidy(height: u64) -> u64 {
    let s = height / HALVING;
    if s >= 64 { 0 } else { (50 * COIN) >> s }
}
/// 难度调整（§4.5）。
pub fn next_bits(c: &Chain) -> u32 {
    let tip = match c.blocks.last() { Some(b) => b, None => return 0x1f0f_ffff };
    if (c.height() + 1) % RETARGET != 0 { return tip.bits }
    let expect = RETARGET as i64 * SPACING;
    let base = c.blocks[(c.height() + 1 - RETARGET) as usize].time;
    let span = (c.tip_time() - base).clamp(expect / 4, expect * 4);
    let (mut exp, mant) = (tip.bits >> 24, tip.bits & 0xff_ffff);
    let mut m2 = mant as u64 * span as u64 / expect as u64;
    m2 = m2.clamp(mant as u64 / 4, mant as u64 * 4);
    if m2 == 0 { return tip.bits }
    while m2 > 0xff_ffff { m2 >>= 8; exp += 1 }
    while m2 < 0x1_0000 && exp > 3 { m2 <<= 8; exp -= 1 }
    if exp > 0xff { return 0xff_ffff_ff }
    (exp << 24) | m2 as u32
}
/// 创世 bits：环境变量 ATL_BITS（hex），缺省 0x1f0fffff。
pub fn genesis_bits() -> u32 {
    std::env::var("ATL_BITS").ok()
        .and_then(|s| u32::from_str_radix(s.trim().trim_start_matches("0x").trim_start_matches("0X"), 16).ok())
        .filter(|b| *b != 0 && target(*b) != [0u8; 32])
        .unwrap_or(0x1f0f_ffff)
}

/// 区块链 + UTXO 集合（blocks[0] 为创世块），`Chain` 派生 `Clone`（SPEC §9）。
#[derive(Clone)]
pub struct Chain { pub blocks: Vec<Block>, pub utxo: HashMap<OutPoint, TxOut> }

impl Chain {
    /// 创世块：prev=[0;32], time=GENESIS_TIME, bits=genesis_bits()，nonce 已挖好。
    pub fn new(genesis_addr: [u8; 20]) -> Chain {
        let cb = Tx {
            time: GENESIS_TIME,
            ins: vec![TxIn { prev: OutPoint { txid: [0; 32], idx: u32::MAX }, sig: vec![], pk: vec![] }],
            outs: vec![TxOut { value: subsidy(0), addr: genesis_addr }],
        };
        let mut b = Block { prev: [0; 32], time: GENESIS_TIME, bits: genesis_bits(), nonce: 0, txs: vec![cb] };
        let mut c = Chain { blocks: Vec::new(), utxo: HashMap::new() };
        c.mine_block(&mut b);
        c.apply(&b);
        c.blocks.push(b);
        c
    }
    pub fn height(&self) -> u64 { self.blocks.len().saturating_sub(1) as u64 }
    pub fn tip(&self) -> [u8; 32] { self.blocks.last().map(|b| b.hash()).unwrap_or([0; 32]) }
    pub fn tip_time(&self) -> i64 { self.blocks.last().map(|b| b.time).unwrap_or(GENESIS_TIME) }
    pub fn balance(&self, addr: &[u8; 20]) -> u64 {
        self.utxo.values().filter(|o| &o.addr == addr).fold(0u64, |a, o| a.saturating_add(o.value))
    }
    pub fn utxos_of(&self, addr: &[u8; 20]) -> Vec<(OutPoint, TxOut)> {
        let mut v: Vec<_> = self.utxo.iter().filter(|(_, o)| &o.addr == addr).map(|(k, o)| (*k, o.clone())).collect();
        v.sort_by_key(|(k, _)| *k);
        v
    }
    /// 校验普通交易（§4.4），返回手续费。
    pub fn validate_tx(&self, tx: &Tx, extra_spent: &HashSet<OutPoint>) -> Result<u64, String> {
        if tx.is_coinbase() { return Err("coinbase not allowed here".into()) }
        if tx.ins.is_empty() { return Err("no inputs".into()) }
        if tx.outs.is_empty() { return Err("no outputs".into()) }
        if tx.outs.iter().any(|o| o.value == 0) { return Err("zero output value".into()) }
        // 规则 3（全部输入先查存在性与冲突），再规则 4（全部输入再验签）：与 SPEC §4.4 顺序一致，
        // 这样"重复输入"报 already spent 而不是被前面的签名错误掩盖。
        let mut seen: HashSet<OutPoint> = HashSet::new();
        let mut sum_in = 0u64;
        for inp in tx.ins.iter() {
            if extra_spent.contains(&inp.prev) || !seen.insert(inp.prev) { return Err("input already spent".into()) }
            let out = self.utxo.get(&inp.prev).ok_or("missing utxo")?;
            sum_in = sum_in.checked_add(out.value).ok_or("input overflow")?;
        }
        for (i, inp) in tx.ins.iter().enumerate() {
            let out = &self.utxo[&inp.prev];
            let pk: [u8; 33] = inp.pk.as_slice().try_into().map_err(|_| "bad pk length")?;
            if secp::addr(&pk) != out.addr { return Err("pk does not own utxo".into()) }
            let sig: [u8; 64] = inp.sig.as_slice().try_into().map_err(|_| "bad sig length")?;
            if !secp::verify(&pk, &tx.signing_hash(i), &sig) { return Err("bad signature".into()) }
        }
        let sum_out = tx.outs.iter().try_fold(0u64, |a, o| a.checked_add(o.value)).ok_or("output overflow")?;
        if sum_in < sum_out { return Err("inputs < outputs".into()) }
        Ok(sum_in - sum_out)
    }
    /// 组块：自动加 coinbase（subsidy(height+1)+fees），bits=next_bits。
    pub fn build_block(&self, addr: &[u8; 20], txs: &[Tx], time: i64) -> Block {
        let no = HashSet::new();
        let fee = txs.iter().filter_map(|t| self.validate_tx(t, &no).ok()).fold(0u64, |a, f| a.saturating_add(f));
        let cb = Tx {
            time,
            ins: vec![TxIn { prev: OutPoint { txid: [0; 32], idx: u32::MAX }, sig: vec![], pk: vec![] }],
            outs: vec![TxOut { value: subsidy(self.height() + 1).saturating_add(fee), addr: *addr }],
        };
        let mut all = Vec::with_capacity(txs.len() + 1);
        all.push(cb);
        all.extend(txs.iter().cloned());
        Block { prev: self.tip(), time, bits: next_bits(self), nonce: 0, txs: all }
    }
    /// 递增 nonce 直到 pow_ok（不改 time）。
    pub fn mine_block(&self, b: &mut Block) {
        while !pow_ok(&b.hash(), b.bits) { b.nonce = b.nonce.wrapping_add(1) }
    }
    /// 校验并落账（§4.5）。
    pub fn add_block(&mut self, b: &Block) -> Result<(), String> {
        if b.prev != self.tip() { return Err("prev != tip".into()) }
        let ids: Vec<[u8; 32]> = b.txs.iter().map(|t| t.id()).collect();
        if b.merkle() != hash::merkle(&ids) { return Err("bad merkle".into()) }
        if b.bits != next_bits(self) { return Err("bad bits".into()) }
        if !pow_ok(&b.hash(), b.bits) { return Err("bad pow".into()) }
        let mut ts: Vec<i64> = self.blocks.iter().rev().take(11).map(|x| x.time).collect();
        ts.sort_unstable();
        if b.time <= ts[ts.len() / 2] { return Err("bad time".into()) }
        let first = b.txs.first().ok_or("empty block")?;
        if !first.is_coinbase() { return Err("first tx is not coinbase".into()) }
        if b.txs.iter().skip(1).any(|t| t.is_coinbase()) { return Err("extra coinbase".into()) }
        let mut spent: HashSet<OutPoint> = HashSet::new();
        let mut fees = 0u64;
        for t in b.txs.iter().skip(1) {
            fees = fees.saturating_add(self.validate_tx(t, &spent)?);
            spent.extend(t.ins.iter().map(|i| i.prev));
        }
        let cbtotal = first.outs.iter().fold(0u64, |a, o| a.saturating_add(o.value));
        if cbtotal > subsidy(self.height() + 1).saturating_add(fees) { return Err("coinbase overpay".into()) }
        self.apply(b);
        self.blocks.push(b.clone());
        Ok(())
    }
    /// 落账：删已花费 utxo，加新输出（idx 为输出下标）。
    fn apply(&mut self, b: &Block) {
        for t in &b.txs {
            let id = t.id();
            if !t.is_coinbase() { for i in &t.ins { self.utxo.remove(&i.prev); } }
            for (j, o) in t.outs.iter().enumerate() { self.utxo.insert(OutPoint { txid: id, idx: j as u32 }, o.clone()); }
        }
    }
}

/// 内存池。
pub struct Mempool { pub txs: Vec<Tx> }
impl Mempool {
    pub fn new() -> Self { Mempool { txs: Vec::new() } }
    /// 校验后入池（重复 txid 拒绝）。
    pub fn add(&mut self, c: &Chain, tx: Tx) -> Result<(), String> {
        if self.txs.iter().any(|t| t.id() == tx.id()) { return Err("tx already in mempool".into()) }
        c.validate_tx(&tx, &HashSet::new())?;
        self.txs.push(tx);
        Ok(())
    }
    pub fn remove(&mut self, ids: &[[u8; 32]]) { self.txs.retain(|t| !ids.contains(&t.id())) }
    /// 丢弃已上链（utxo 已消费）或已非法的交易。
    pub fn clean(&mut self, c: &Chain) {
        let no = HashSet::new();
        self.txs.retain(|t| c.validate_tx(t, &no).is_ok())
    }
    /// 仍可打包的交易（依赖/冲突过滤）。
    pub fn select(&self, c: &Chain) -> Vec<Tx> {
        let mut spent: HashSet<OutPoint> = HashSet::new();
        let mut out = Vec::new();
        for t in &self.txs {
            if c.validate_tx(t, &spent).is_ok() {
                spent.extend(t.ins.iter().map(|i| i.prev));
                out.push(t.clone());
            }
        }
        out
    }
}
