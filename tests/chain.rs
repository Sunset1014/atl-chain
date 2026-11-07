//! 链、交易、共识与内存池测试 —— SPEC §4 与 §10 tests/chain.rs。
//!
//! 只在内存里构造链，不碰磁盘与网络；难度用默认 `0x1f0fffff`（约 4096 次哈希，毫秒级）。

use blockchain::chain::{
    self, next_bits, pow_ok, subsidy, target, Block, Chain, Mempool, OutPoint, Tx, TxIn, TxOut, COIN,
    GENESIS_TIME, HALVING, MAX_FRAME, RETARGET, SPACING,
};
use blockchain::codec::Rd;
use blockchain::hash::{merkle, sha256d};
use blockchain::secp;
use blockchain::wallet::{self, Key};
use std::collections::{HashMap, HashSet};

/// 造一条只含创世块的链（创世地址固定为 [0;20]）。
fn genesis_chain() -> Chain {
    Chain::new(chain::GENESIS_ADDR)
}

/// 组块 + 挖到满足难度，返回已挖好的块（尚未入链）。
fn mint(c: &Chain, addr: [u8; 20], txs: &[Tx], time: i64) -> Block {
    let mut b = c.build_block(&addr, txs, time);
    c.mine_block(&mut b);
    b
}

/// 找一个必然不满足当前难度的 nonce，用于「坏 PoW」测试（确定性，不会碰巧通过）。
fn nonce_failing_pow(b: &Block) -> u32 {
    let mut n = b.nonce.wrapping_add(1);
    loop {
        let mut probe = b.clone();
        probe.nonce = n;
        if !pow_ok(&probe.hash(), probe.bits) {
            return n;
        }
        n = n.wrapping_add(1);
    }
}

/// 把 tx 的所有输入重新签名（用于「改了输出之后仍要验证签名之外规则」的场景）。
fn resign(tx: &mut Tx, k: &Key) {
    for i in 0..tx.ins.len() {
        tx.ins[i].sig = secp::sign(&k.sk, &tx.signing_hash(i)).to_vec();
        tx.ins[i].pk = k.pk.to_vec();
    }
}

#[test]
fn genesis_block_matches_spec() {
    let addr = [0u8; 20];
    let c = Chain::new(addr);
    assert_eq!(c.blocks.len(), 1, "创世链必须恰好有 1 个块");
    assert_eq!(c.height(), 0, "创世块高度必须是 0");

    let b = &c.blocks[0];
    assert_eq!(b.prev, [0u8; 32], "创世块 prev 必须是全 0");
    assert_eq!(b.time, GENESIS_TIME, "创世块时间必须是 GENESIS_TIME");
    assert_eq!(b.bits, chain::genesis_bits(), "创世块 bits 必须来自 genesis_bits()");
    assert!(pow_ok(&b.hash(), b.bits), "创世块必须满足 PoW，bits=0x{:08x}", b.bits);
    assert_eq!(b.txs.len(), 1, "创世块必须恰好有 1 个 coinbase 交易");

    let cb = &b.txs[0];
    assert!(cb.is_coinbase(), "创世块首笔必须是 coinbase");
    assert_eq!(cb.outs.len(), 1, "创世 coinbase 必须恰好 1 个输出");
    assert_eq!(cb.outs[0].value, 50 * COIN, "创世 coinbase 金额必须是 subsidy(0)=50 COIN");
    assert_eq!(cb.outs[0].value, subsidy(0), "创世 coinbase 金额必须等于 subsidy(0)");
    assert_eq!(cb.outs[0].addr, addr, "创世 coinbase 输出地址必须是传入的创世地址");

    assert_eq!(c.tip(), b.hash(), "空链的 tip 必须是创世块哈希");
    assert_eq!(c.tip_time(), GENESIS_TIME, "空链的 tip_time 必须是创世时间");
    assert_eq!(c.balance(&addr), 50 * COIN, "创世地址余额");
    assert_eq!(c.utxo.len(), 1, "创世后 UTXO 集合只有 1 项");
    let op = OutPoint { txid: cb.id(), idx: 0 };
    assert_eq!(c.utxo.get(&op).map(|o| o.value), Some(50 * COIN), "创世 UTXO 的键必须是 (coinbase_txid, 0)");
    assert_eq!(c.utxos_of(&addr).len(), 1, "utxos_of 必须列出创世 UTXO");
}

#[test]
fn consensus_constants_match_spec() {
    assert_eq!(COIN, 100_000_000, "COIN 必须是 1e8 satoshi");
    assert_eq!(SPACING, 60, "SPACING 必须是 60 秒");
    assert_eq!(HALVING, 210_000, "HALVING 必须是 210000");
    assert_eq!(RETARGET, 2016, "RETARGET 必须是 2016");
    assert_eq!(MAX_FRAME, 4 << 20, "MAX_FRAME 必须是 4 MiB");
    assert_eq!(GENESIS_TIME, 1_700_000_000, "GENESIS_TIME 必须是 1700000000");
    assert_eq!(chain::GENESIS_ADDR, [0u8; 20], "GENESIS_ADDR 必须是全 0 地址");
    if std::env::var("ATL_BITS").is_err() {
        assert_eq!(chain::genesis_bits(), 0x1f0f_ffff, "缺省创世难度必须是 0x1f0fffff");
    }
}

#[test]
fn mine_then_add_block_updates_chain() {
    let miner = [3u8; 20];
    let mut c = genesis_chain();
    let tip0 = c.tip();
    assert_eq!(c.balance(&miner), 0, "挖矿前矿工余额必须为 0");

    let b = mint(&c, miner, &[], GENESIS_TIME + 1);
    assert!(pow_ok(&b.hash(), b.bits), "mine_block 之后必须满足 PoW");
    assert_eq!(b.prev, tip0, "新块的 prev 必须是挖矿前的 tip");
    assert_eq!(b.bits, c.blocks[0].bits, "未到重定目标高度时 bits 必须沿用父块");

    c.add_block(&b).expect("合法区块必须被接受");
    assert_eq!(c.height(), 1, "入链后高度必须是 1");
    assert_eq!(c.tip(), b.hash(), "入链后 tip 必须是新块哈希");
    assert_eq!(c.tip_time(), GENESIS_TIME + 1, "入链后 tip_time");
    assert_eq!(c.balance(&miner), subsidy(1), "矿工必须得到 subsidy(1)");
    assert_eq!(c.balance(&miner), 50 * COIN, "subsidy(1) 必须是 50 COIN");
    assert_eq!(c.utxo.len(), 2, "入链后 UTXO 应为创世 coinbase + 新 coinbase");

    // 同一块再入一次：prev != tip
    let e = c.add_block(&b).expect_err("重复区块必须被拒绝");
    assert!(e.contains("prev"), "重复区块错误信息应提到 prev，实际: {e}");
}

#[test]
fn add_block_rejects_bad_pow() {
    let miner = [4u8; 20];
    let mut c = genesis_chain();
    let good = mint(&c, miner, &[], GENESIS_TIME + 1);

    let mut bad = good.clone();
    bad.nonce = nonce_failing_pow(&good);
    assert!(!pow_ok(&bad.hash(), bad.bits), "构造出来的 nonce 必须不满足 PoW");
    let e = c.add_block(&bad).expect_err("PoW 不达标的区块必须被拒绝");
    assert!(e.contains("pow"), "错误信息应提到 pow，实际: {e}");
    assert_eq!(c.height(), 0, "被拒的区块不得改变链状态");
}

#[test]
fn add_block_rejects_wrong_bits() {
    let miner = [5u8; 20];
    let mut c = genesis_chain();
    let mut bad = mint(&c, miner, &[], GENESIS_TIME + 1);
    bad.bits = 0x1d00_ffff; // 与 next_bits 不一致（更难）
    let e = c.add_block(&bad).expect_err("bits 与 next_bits 不符的区块必须被拒绝");
    assert!(e.contains("bits"), "错误信息应提到 bits，实际: {e}");
    assert_eq!(c.height(), 0, "被拒的区块不得改变链状态");
}

#[test]
fn add_block_rejects_bad_time() {
    let miner = [6u8; 20];
    let mut c = genesis_chain();
    // 时间必须严格大于前 11 个块时间的中位数；等于创世时间应被拒
    let b = mint(&c, miner, &[], GENESIS_TIME);
    let e = c.add_block(&b).expect_err("时间未超过中位数的区块必须被拒绝");
    assert!(e.contains("time"), "错误信息应提到 time，实际: {e}");
}

#[test]
fn add_block_rejects_block_without_coinbase_first() {
    let k = Key::from_seed(b"atl-chain-no-coinbase", 0);
    let mut c = genesis_chain();
    let to = [7u8; 20];
    let b1 = mint(&c, k.addr, &[], GENESIS_TIME + 1);
    c.add_block(&b1).expect("挖到矿工地址的区块必须被接受");

    let tx = wallet::send(&c, &k, to, COIN, 0, GENESIS_TIME + 2).expect("钱包应当能构造交易");
    let mut b = Block { prev: c.tip(), time: GENESIS_TIME + 2, bits: next_bits(&c), nonce: 0, txs: vec![tx] };
    c.mine_block(&mut b);
    let e = c.add_block(&b).expect_err("首笔不是 coinbase 的区块必须被拒绝");
    assert!(e.contains("coinbase"), "错误信息应提到 coinbase，实际: {e}");
}

#[test]
fn add_block_rejects_extra_coinbase() {
    let miner = [8u8; 20];
    let mut c = genesis_chain();
    let mut b = c.build_block(&miner, &[], GENESIS_TIME + 1);
    let cb = b.txs[0].clone();
    b.txs.push(cb);
    c.mine_block(&mut b);
    let e = c.add_block(&b).expect_err("含多个 coinbase 的区块必须被拒绝");
    assert!(e.contains("coinbase"), "错误信息应提到 coinbase，实际: {e}");
}

#[test]
fn add_block_rejects_coinbase_overpay() {
    let miner = [9u8; 20];
    let mut c = genesis_chain();
    let mut b = c.build_block(&miner, &[], GENESIS_TIME + 1);
    b.txs[0].outs[0].value = subsidy(1) + 1; // 多发 1 satoshi
    c.mine_block(&mut b);
    let e = c.add_block(&b).expect_err("coinbase 超额发放必须被拒绝");
    assert!(e.contains("coinbase"), "错误信息应提到 coinbase，实际: {e}");
    assert_eq!(c.balance(&miner), 0, "被拒区块不得给矿工记账");
}

#[test]
fn add_block_rejects_double_spend() {
    let k = Key::from_seed(b"atl-chain-double-spend", 0);
    let mut c = genesis_chain();
    let b1 = mint(&c, k.addr, &[], GENESIS_TIME + 1);
    c.add_block(&b1).expect("给钱包地址挖一块");
    assert_eq!(c.balance(&k.addr), 50 * COIN, "钱包地址应有 50 COIN");

    // 两笔交易花同一个 UTXO（不同 time 保证 txid 不同）
    let tx1 = wallet::send(&c, &k, [21u8; 20], 10 * COIN, 0, GENESIS_TIME + 2).expect("第一笔");
    let tx2 = wallet::send(&c, &k, [22u8; 20], 20 * COIN, 0, GENESIS_TIME + 3).expect("第二笔");
    assert_ne!(tx1.id(), tx2.id(), "两笔冲突交易的 txid 必须不同");
    assert_eq!(tx1.ins[0].prev, tx2.ins[0].prev, "两笔交易必须花同一个 UTXO");

    let mut b = c.build_block(&k.addr, &[tx1, tx2], GENESIS_TIME + 2);
    c.mine_block(&mut b);
    let e = c.add_block(&b).expect_err("同一区块内双花必须被拒绝");
    assert!(e.contains("already spent"), "错误信息应提到 already spent，实际: {e}");
    assert_eq!(c.height(), 1, "被拒区块不得改变高度");
    assert_eq!(c.balance(&k.addr), 50 * COIN, "被拒区块不得改变余额");
}

#[test]
fn validate_tx_accepts_signed_tx_and_returns_fee() {
    let k = Key::from_seed(b"atl-chain-validate", 0);
    let mut c = genesis_chain();
    let b1 = mint(&c, k.addr, &[], GENESIS_TIME + 1);
    c.add_block(&b1).expect("挖块");

    let to = [31u8; 20];
    let fee = COIN / 2;
    let tx = wallet::send(&c, &k, to, 40 * COIN, fee, GENESIS_TIME + 2).expect("钱包应当能构造交易");
    let got = c.validate_tx(&tx, &HashSet::new()).expect("合法交易必须通过校验");
    assert_eq!(got, fee, "validate_tx 必须返回 sum(in)-sum(out) 作为手续费");
    assert_eq!(tx.outs[0], TxOut { value: 40 * COIN, addr: to }, "第一个输出必须付给收款方");
    assert_eq!(
        tx.outs[1],
        TxOut { value: 10 * COIN - fee, addr: k.addr },
        "找零必须回到付款方地址"
    );
    assert_eq!(tx.ins.len(), 1, "该笔转账只需 1 个输入");
    assert_eq!(tx.ins[0].sig.len(), 64, "签名必须 64 字节");
    assert_eq!(tx.ins[0].pk.len(), 33, "公钥必须 33 字节（压缩）");
}

#[test]
fn validate_tx_rejects_bad_signature() {
    let k = Key::from_seed(b"atl-chain-badsig", 0);
    let mut c = genesis_chain();
    let b1 = mint(&c, k.addr, &[], GENESIS_TIME + 1);
    c.add_block(&b1).expect("挖块");
    let mut tx = wallet::send(&c, &k, [41u8; 20], COIN, 0, GENESIS_TIME + 2).expect("构交易");

    tx.ins[0].sig[0] ^= 0x01;
    let e = c.validate_tx(&tx, &HashSet::new()).expect_err("签名被篡改必须失败");
    assert!(e.contains("signature"), "错误信息应提到 signature，实际: {e}");
}

#[test]
fn validate_tx_rejects_foreign_pubkey_and_missing_utxo() {
    let k = Key::from_seed(b"atl-chain-foreign", 0);
    let other = Key::from_seed(b"atl-chain-foreign", 1);
    let mut c = genesis_chain();
    let b1 = mint(&c, k.addr, &[], GENESIS_TIME + 1);
    c.add_block(&b1).expect("挖块");

    // 用别人的公钥花 k 的钱
    let mut tx = wallet::send(&c, &k, [51u8; 20], COIN, 0, GENESIS_TIME + 2).expect("构交易");
    tx.ins[0].pk = other.pk.to_vec();
    tx.ins[0].sig = secp::sign(&other.sk, &tx.signing_hash(0)).to_vec();
    let e = c.validate_tx(&tx, &HashSet::new()).expect_err("公钥不拥有该 UTXO 必须失败");
    assert!(e.contains("own"), "错误信息应提到 pk does not own utxo，实际: {e}");

    // 引用不存在的 UTXO
    let mut tx2 = wallet::send(&c, &k, [52u8; 20], COIN, 0, GENESIS_TIME + 3).expect("构交易");
    tx2.ins[0].prev.idx = 9;
    let e2 = c.validate_tx(&tx2, &HashSet::new()).expect_err("引用不存在的 UTXO 必须失败");
    assert!(e2.contains("utxo"), "错误信息应提到 missing utxo，实际: {e2}");

    // 传入 extra_spent 时必须拒绝
    let tx3 = wallet::send(&c, &k, [53u8; 20], COIN, 0, GENESIS_TIME + 4).expect("构交易");
    let mut spent = HashSet::new();
    spent.insert(tx3.ins[0].prev);
    let e3 = c.validate_tx(&tx3, &spent).expect_err("extra_spent 中的输入必须被拒绝");
    assert!(e3.contains("already spent"), "错误信息应提到 already spent，实际: {e3}");
}

#[test]
fn validate_tx_rejects_shapes_and_overspend() {
    let k = Key::from_seed(b"atl-chain-shapes", 0);
    let mut c = genesis_chain();
    let b1 = mint(&c, k.addr, &[], GENESIS_TIME + 1);
    c.add_block(&b1).expect("挖块");

    // 空输入 / 空输出
    let no_in = Tx { time: GENESIS_TIME + 2, ins: vec![], outs: vec![TxOut { value: 1, addr: [0u8; 20] }] };
    assert!(
        c.validate_tx(&no_in, &HashSet::new()).unwrap_err().contains("input"),
        "空输入必须被拒绝"
    );
    let no_out = Tx {
        time: GENESIS_TIME + 2,
        ins: vec![TxIn { prev: OutPoint { txid: [0u8; 32], idx: 0 }, sig: vec![], pk: vec![] }],
        outs: vec![],
    };
    assert!(
        c.validate_tx(&no_out, &HashSet::new()).unwrap_err().contains("output"),
        "空输出必须被拒绝"
    );

    // 0 金额输出
    let mut tx = wallet::send(&c, &k, [61u8; 20], COIN, 0, GENESIS_TIME + 3).expect("构交易");
    tx.outs[0].value = 0;
    resign(&mut tx, &k);
    let e = c.validate_tx(&tx, &HashSet::new()).expect_err("0 金额输出必须被拒绝");
    assert!(e.contains("zero"), "错误信息应提到 zero output value，实际: {e}");

    // 超发：输出总额 > 输入总额（改完输出后重新签名，确保不是签名问题）
    let mut tx2 = wallet::send(&c, &k, [62u8; 20], 50 * COIN, 0, GENESIS_TIME + 4).expect("构交易");
    tx2.outs[0].value = 50 * COIN + 1;
    resign(&mut tx2, &k);
    let e2 = c.validate_tx(&tx2, &HashSet::new()).expect_err("输出总额超过输入必须被拒绝");
    assert!(e2.contains("inputs < outputs"), "错误信息应提到 inputs < outputs，实际: {e2}");

    // 同一交易内重复输入
    let tx3 = wallet::send(&c, &k, [63u8; 20], COIN, 0, GENESIS_TIME + 5).expect("构交易");
    let dup = tx3.ins[0].clone();
    let mut tx4 = tx3.clone();
    tx4.ins.push(dup);
    let e3 = c.validate_tx(&tx4, &HashSet::new()).expect_err("同一交易内重复输入必须被拒绝");
    assert!(e3.contains("already spent"), "错误信息应提到 already spent，实际: {e3}");
}

#[test]
fn validate_tx_rejects_coinbase() {
    let c = genesis_chain();
    let cb = c.blocks[0].txs[0].clone();
    let e = c.validate_tx(&cb, &HashSet::new()).expect_err("coinbase 不得走 validate_tx");
    assert!(e.contains("coinbase"), "错误信息应提到 coinbase，实际: {e}");
}

#[test]
fn subsidy_halves_every_210000_blocks() {
    assert_eq!(subsidy(0), 50 * COIN, "subsidy(0) = 50 COIN");
    assert_eq!(subsidy(HALVING - 1), 50 * COIN, "第一次减半前保持 50 COIN");
    assert_eq!(subsidy(HALVING), 25 * COIN, "subsidy(210000) = 25 COIN");
    assert_eq!(subsidy(HALVING * 2), 1_250_000_000, "subsidy(420000) = 12.5 COIN");
    assert_eq!(subsidy(HALVING * 3), 625_000_000, "subsidy(630000) = 6.25 COIN");
    assert_eq!(subsidy(HALVING * 63), 0, "位移 >= 64 之前总额已下溢到 0");
    assert_eq!(subsidy(HALVING * 64), 0, "位移 >= 64 必须记 0");
    assert_eq!(subsidy(u64::MAX), 0, "极大高度必须返回 0 而不是 panic");
}

#[test]
fn target_decodes_compact_bits() {
    let t = target(0x1f0f_ffff);
    assert_eq!(t[0], 0x00, "0x1f0fffff 的目标值最高字节必须是 0x00");
    assert_eq!(t[1], 0x0f, "0x1f0fffff 的目标值第二字节必须是 0x0f");
    assert_eq!(&t[2..4], &[0xff, 0xff], "0x1f0fffff 的目标值接下来两字节必须是 ff ff");
    assert_eq!(&t[4..], &[0u8; 28], "0x1f0fffff 的目标值其余字节必须为 0");

    let btc = target(0x1d00_ffff);
    assert_eq!(&btc[..4], &[0, 0, 0, 0], "0x1d00ffff（比特币创世参数）前 4 字节必须为 0");
    assert_eq!(&btc[4..6], &[0xff, 0xff], "0x1d00ffff 的 0xffff 起点在第 4 字节");
    assert_eq!(target(0), [0u8; 32], "mant == 0 时目标值必须是全 0");
}

#[test]
fn pow_boundary_is_inclusive() {
    let bits = 0x1f0f_ffff;
    let t = target(bits);
    assert!(pow_ok(&t, bits), "哈希恰好等于目标值必须算通过（<=）");
    let mut above = t;
    above[1] = 0x10; // 比目标值的第二字节大
    assert!(!pow_ok(&above, bits), "哈希略大于目标值必须失败");
    let mut tail = t;
    tail[31] = 1; // 只有最低字节大 1
    assert!(!pow_ok(&tail, bits), "最低字节略大也必须失败（按大端整数值比较）");
    assert!(pow_ok(&[0u8; 32], bits), "全 0 哈希必然通过任何非零目标");
    assert!(!pow_ok(&[0xffu8; 32], bits), "全 ff 哈希必然失败");
}

/// 手工拼一条只有时间/难度字段的链，用来精确测 next_bits 的重定目标公式。
fn fake_chain(times: &[i64], bits: u32) -> Chain {
    let blocks = times
        .iter()
        .map(|t| Block { prev: [0u8; 32], time: *t, bits, nonce: 0, txs: vec![] })
        .collect();
    Chain { blocks, utxo: HashMap::new() }
}

#[test]
fn next_bits_holds_bits_below_retarget() {
    let c = fake_chain(&[GENESIS_TIME, GENESIS_TIME + 1000], 0x1f0f_ffff);
    assert_eq!(c.height(), 1, "假链高度应为 1");
    assert_eq!(next_bits(&c), 0x1f0f_ffff, "未到 RETARGET 边界时必须沿用父块 bits");

    let mut c2 = fake_chain(&vec![GENESIS_TIME; 100], 0x1c0f_ffff);
    assert_eq!(next_bits(&c2), 0x1c0f_ffff, "未到边界时无论时间如何都不调整难度");
    // 空链（没有区块）也必须给出缺省难度而不是 panic
    c2.blocks.clear();
    assert_eq!(next_bits(&c2), 0x1f0f_ffff, "空链的 next_bits 必须返回缺省 0x1f0fffff");
}

#[test]
fn next_bits_retargets_at_boundary() {
    // 构造 2016 个块（高度 2015），下一次高度 2016 正好落在 RETARGET 边界上
    let bits = 0x1f0f_ffff;
    let expect = RETARGET as i64 * SPACING;

    // ① 实际跨度恰好等于期望 -> bits 不变
    let mut times: Vec<i64> = (0..RETARGET).map(|i| GENESIS_TIME + i as i64 * SPACING).collect();
    times[(RETARGET - 1) as usize] = GENESIS_TIME + expect;
    let c = fake_chain(&times, bits);
    assert_eq!(c.height(), 2015, "假链高度必须是 2015");
    assert_eq!(next_bits(&c), bits, "跨度等于期望时难度必须不变");

    // ② 出块过快（跨度被限幅到 expect/4）-> mant 变为 1/4
    let mut fast = times.clone();
    let base = fast[0];
    fast[(RETARGET - 1) as usize] = base + expect / 8;
    let c2 = fake_chain(&fast, bits);
    let mant = (bits & 0x00ff_ffff) / 4;
    assert_eq!(
        next_bits(&c2),
        (bits & 0xff00_0000) | mant,
        "出块过快时 m2 必须按 expect/4 限幅后变为 mant/4"
    );

    // ③ 出块过慢（跨度被限幅到 expect*4）-> mant 变为 4 倍
    let mut slow = times;
    let base_s = slow[0];
    slow[(RETARGET - 1) as usize] = base_s + expect * 8;
    let c3 = fake_chain(&slow, bits);
    let mant3 = (bits & 0x00ff_ffff) * 4;
    assert_eq!(
        next_bits(&c3),
        (bits & 0xff00_0000) | mant3,
        "出块过慢时 m2 必须按 expect*4 限幅后变为 mant*4"
    );
}

#[test]
fn tx_encoding_roundtrip_and_signing_hash() {
    let k = Key::from_seed(b"atl-chain-encode", 0);
    let mut c = genesis_chain();
    let b1 = mint(&c, k.addr, &[], GENESIS_TIME + 1);
    c.add_block(&b1).expect("挖块");
    let tx = wallet::send(&c, &k, [71u8; 20], COIN, 3, GENESIS_TIME + 2).expect("构交易");

    let enc = tx.enc();
    let mut r = Rd::new(&enc);
    let dec = Tx::dec(&mut r).expect("交易必须可解码");
    assert_eq!(r.rest(), 0, "解码后不得有剩余字节");
    assert_eq!(dec.enc(), enc, "重新编码必须与原始字节一致");
    assert_eq!(dec.id(), tx.id(), "往返后 txid 必须一致");
    assert_eq!(tx.id(), sha256d(&enc), "txid 必须是 sha256d(enc())");
    assert!(!tx.is_coinbase(), "普通交易不能被认成 coinbase");

    // signing_hash(i) = sha256d(enc_nosig() || i as u32 LE)
    let mut nosig = tx.clone();
    for i in &mut nosig.ins {
        i.sig.clear();
        i.pk.clear();
    }
    let mut buf = nosig.enc();
    buf.extend_from_slice(&0u32.to_le_bytes());
    assert_eq!(tx.signing_hash(0), sha256d(&buf), "signing_hash(0) 必须按 SPEC 公式计算");
    assert_ne!(tx.signing_hash(0), tx.signing_hash(1), "不同输入下标的签名哈希必须不同");
    assert_ne!(tx.signing_hash(0), tx.id(), "签名哈希不能等于 txid（必须清空 sig/pk）");
}

#[test]
fn block_encoding_roundtrip_and_hash() {
    let k = Key::from_seed(b"atl-chain-blockenc", 0);
    let mut c = genesis_chain();
    let b1 = mint(&c, k.addr, &[], GENESIS_TIME + 1);
    c.add_block(&b1).expect("挖块");
    let tx = wallet::send(&c, &k, [81u8; 20], COIN, 1, GENESIS_TIME + 2).expect("构交易");
    let b = mint(&c, [82u8; 20], &[tx.clone()], GENESIS_TIME + 2);

    assert_eq!(b.header().len(), 48, "区块头必须是 32+8+4+4=48 字节");
    assert_eq!(b.hash(), sha256d(&b.header()), "区块哈希必须是 sha256d(header())");
    let ids: Vec<[u8; 32]> = b.txs.iter().map(|t| t.id()).collect();
    assert_eq!(b.merkle(), merkle(&ids), "merkle 根必须等于所有 txid 的 merkle");
    assert_eq!(b.txs.len(), 2, "区块应为 coinbase + 1 笔普通交易");
    assert!(b.txs[0].is_coinbase(), "区块首笔必须是 coinbase");

    let enc = b.enc();
    let mut r = Rd::new(&enc);
    let dec = Block::dec(&mut r).expect("区块必须可解码");
    assert_eq!(r.rest(), 0, "解码后不得有剩余字节");
    assert_eq!(dec.enc(), enc, "重新编码必须与原始字节一致");
    assert_eq!(dec.hash(), b.hash(), "往返后区块哈希必须一致");
    assert_eq!(dec.merkle(), b.merkle(), "往返后 merkle 必须一致");
    assert_eq!(dec.txs[1].id(), tx.id(), "往返后交易必须一致");
}

#[test]
fn block_encoding_rejects_truncated_input() {
    let c = genesis_chain();
    let enc = c.blocks[0].enc();
    for cut in [0usize, 1, 40, 47, 48] {
        let mut r = Rd::new(&enc[..cut.min(enc.len())]);
        assert!(Block::dec(&mut r).is_none(), "截断到 {cut} 字节的区块必须解码失败");
    }
    // 多一个字节也必须能容忍吗？不：dec 只消费自己需要的字节，剩下的留给调用方。
    let mut long = enc.clone();
    long.push(0xee);
    let mut r = Rd::new(&long);
    let dec = Block::dec(&mut r).expect("多出的尾部字节不应导致解码失败");
    assert_eq!(dec.hash(), c.blocks[0].hash(), "多余尾部字节不得影响区块内容");
    assert_eq!(r.rest(), 1, "解码只应消费区块本身的字节");
}

#[test]
fn mempool_add_select_clean() {
    let k = Key::from_seed(b"atl-chain-mempool", 0);
    let mut c = genesis_chain();
    let b1 = mint(&c, k.addr, &[], GENESIS_TIME + 1);
    c.add_block(&b1).expect("挖块");

    let tx1 = wallet::send(&c, &k, [91u8; 20], COIN, 0, GENESIS_TIME + 2).expect("构交易");
    let tx2 = wallet::send(&c, &k, [92u8; 20], 2 * COIN, 0, GENESIS_TIME + 3).expect("构冲突交易");

    let mut m = Mempool::new();
    assert!(m.txs.is_empty(), "新内存池必须为空");
    m.add(&c, tx1.clone()).expect("合法交易应入池");
    let e = m.add(&c, tx1.clone()).expect_err("重复 txid 必须被拒绝");
    assert!(e.contains("already in mempool"), "错误信息应提到 already in mempool，实际: {e}");
    m.add(&c, tx2.clone()).expect("add 不做冲突检测，冲突交易也应入池");
    assert_eq!(m.txs.len(), 2, "内存池应有 2 笔交易");

    let picked = m.select(&c);
    assert_eq!(picked.len(), 1, "select 必须过滤掉花同一 UTXO 的冲突交易");
    assert_eq!(picked[0].id(), tx1.id(), "select 必须保留先入池的那笔");

    // tx1 上链后：tx1 因 utxo 已花费失效，tx2 也因输入被花而失效 -> clean 清空
    let b2 = mint(&c, k.addr, &[tx1.clone()], GENESIS_TIME + 2);
    c.add_block(&b2).expect("含 tx1 的区块必须被接受");
    m.clean(&c);
    assert!(m.txs.is_empty(), "上链后 clean 必须丢弃已确认/已失效的交易，实际剩 {} 笔", m.txs.len());
    assert!(c.validate_tx(&tx2, &HashSet::new()).is_err(), "tx2 的输入已被 tx1 花掉，必须失效");

    // remove 按 id 精确删除
    let mut m2 = Mempool::new();
    let tx3 = wallet::send(&c, &Key::from_seed(b"atl-chain-mempool", 0), [93u8; 20], COIN, 0, GENESIS_TIME + 4);
    if let Ok(tx3) = tx3 {
        m2.add(&c, tx3.clone()).expect("入池");
        m2.remove(&[tx3.id()]);
        assert!(m2.txs.is_empty(), "remove 之后内存池必须为空");
    }
}

#[test]
fn chain_is_clone_and_independent() {
    let mut c = genesis_chain();
    let b = mint(&c, [99u8; 20], &[], GENESIS_TIME + 1);
    c.add_block(&b).expect("挖块");
    let snapshot = c.clone();
    assert_eq!(snapshot.height(), c.height(), "克隆后高度必须一致");
    assert_eq!(snapshot.tip(), c.tip(), "克隆后 tip 必须一致");
    assert_eq!(snapshot.utxo.len(), c.utxo.len(), "克隆后 UTXO 数量必须一致");

    let b2 = mint(&c, [98u8; 20], &[], GENESIS_TIME + 2);
    c.add_block(&b2).expect("再挖一块");
    assert_eq!(snapshot.height(), 1, "原链推进不得影响克隆快照");
    assert_eq!(c.height(), 2, "原链高度应为 2");
}
