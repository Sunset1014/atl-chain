//! 钱包与转账测试 —— SPEC §5（密钥派生、找零、手续费）与 §10 tests/wallet.rs。
//!
//! 全部在内存里构造链，不碰磁盘与网络；难度用默认 `0x1f0fffff`（约 4096 次哈希）。

use blockchain::chain::{
    subsidy, Chain, Mempool, OutPoint, Tx, COIN, GENESIS_ADDR, GENESIS_TIME,
};
use blockchain::hash::sha256;
use blockchain::secp;
use blockchain::wallet::{self, Key};
use std::collections::HashSet;

/// 创世块之后的第一个时间戳（add_block 要求新区块时间严格大于最近 11 块的中位数）。
const T1: i64 = GENESIS_TIME + 1;

/// 组块 + 挖到满足难度 + 入链；返回已入链的区块。
fn mine_to(c: &mut Chain, addr: [u8; 20], txs: &[Tx], time: i64) -> blockchain::chain::Block {
    let mut b = c.build_block(&addr, txs, time);
    c.mine_block(&mut b);
    c.add_block(&b)
        .unwrap_or_else(|e| panic!("自己挖出的区块必须被接受，却被拒绝: {e}"));
    b
}

/// 造一条只有创世块 + 一个 50 COIN coinbase 给 `seed` 派生私钥的链。
fn chain_with_coins(seed: &[u8]) -> (Chain, Key) {
    let k = Key::from_seed(seed, 0);
    let mut c = Chain::new(GENESIS_ADDR);
    mine_to(&mut c, k.addr, &[], T1);
    assert_eq!(
        c.balance(&k.addr),
        subsidy(1),
        "挖出一块后该地址余额必须等于 subsidy(1)"
    );
    (c, k)
}

#[test]
fn key_derivation_matches_spec_formula() {
    let seed = b"atl-wallet-test";
    let k = Key::from_seed(seed, 0);

    // SPEC §5：sk = sha256(b"ATL-wallet" || seed || idx.to_le_bytes())
    let mut buf = b"ATL-wallet".to_vec();
    buf.extend_from_slice(seed);
    buf.extend_from_slice(&0u32.to_le_bytes());
    assert_eq!(
        k.sk,
        sha256(&buf),
        "私钥必须等于 sha256(b\"ATL-wallet\" || seed || idx_le)"
    );

    // 公钥 = sk*G，地址 = h160(公钥)
    assert_eq!(k.pk, secp::pubkey(&k.sk), "pk 必须是 sk*G 的压缩公钥");
    assert_eq!(k.addr, secp::addr(&k.pk), "addr 必须是 h160(pk)");
    assert!(
        secp::decode(&k.pk).is_some(),
        "压缩公钥必须能被 secp::decode 解回曲线点"
    );
    assert_ne!(k.sk, [0u8; 32], "私钥不得为 0");
}

#[test]
fn key_from_seed_is_deterministic_and_index_separated() {
    let a = Key::from_seed(b"same-seed", 0);
    let b = Key::from_seed(b"same-seed", 0);
    assert_eq!(a.sk, b.sk, "相同 seed/index 必须确定性派生出相同私钥");
    assert_eq!(a.pk, b.pk, "相同 seed/index 必须派生出相同公钥");
    assert_eq!(a.addr, b.addr, "相同 seed/index 必须派生出相同地址");

    let c = Key::from_seed(b"same-seed", 1);
    assert_ne!(a.sk, c.sk, "不同 index 必须派生出不同私钥");
    assert_ne!(a.addr, c.addr, "不同 index 必须派生出不同地址");

    let d = Key::from_seed(b"other-seed", 0);
    assert_ne!(a.sk, d.sk, "不同 seed 必须派生出不同私钥");
}

#[test]
fn key_hex_roundtrips_and_rejects_bad_input() {
    let k = Key::from_seed(b"hex-seed", 7);
    let hex = k.hex();
    assert_eq!(hex.len(), 64, "私钥 hex 必须是 64 个字符");
    assert!(
        hex.chars().all(|c| c.is_ascii_hexdigit()),
        "私钥 hex 只能含十六进制字符: {hex}"
    );

    let back = Key::from_hex(&hex).expect("合法 32 字节 hex 必须能还原出 Key");
    assert_eq!(back.sk, k.sk, "还原后的私钥必须相同");
    assert_eq!(back.pk, k.pk, "还原后的公钥必须相同");
    assert_eq!(back.addr, k.addr, "还原后的地址必须相同");

    assert!(Key::from_hex("").is_none(), "空串不是合法私钥");
    assert!(Key::from_hex("zz").is_none(), "非十六进制字符必须被拒绝");
    assert!(
        Key::from_hex(&"11".repeat(31)).is_none(),
        "31 字节的输入必须被拒绝"
    );
    assert!(
        Key::from_hex(&"11".repeat(33)).is_none(),
        "33 字节的输入必须被拒绝"
    );
}

#[test]
fn new_seed_is_not_constant() {
    let seeds: Vec<[u8; 32]> = (0..8).map(|_| wallet::new_seed()).collect();
    let uniq: HashSet<[u8; 32]> = seeds.iter().cloned().collect();
    assert!(
        uniq.len() >= 2,
        "new_seed 连续调用 8 次必须至少产生 2 个不同种子（实际 {uniq_len} 个）",
        uniq_len = uniq.len()
    );
}

#[test]
fn send_pays_recipient_and_returns_change() {
    let (c, k) = chain_with_coins(b"send-change");
    let to = Key::from_seed(b"recipient", 0).addr;
    let amount = 3 * COIN;
    let fee = 1_000_u64;

    let tx = wallet::send(&c, &k, to, amount, fee, T1 + 1).expect("余额充足时 send 必须成功");
    assert_eq!(tx.ins.len(), 1, "一个 50 COIN 的 utxo 足够，应该只选一个输入");
    assert_eq!(tx.outs.len(), 2, "有找零时必须产生两个输出");

    assert_eq!(tx.outs[0].value, amount, "第一个输出必须恰好是转账金额");
    assert_eq!(tx.outs[0].addr, to, "第一个输出必须付给收款地址");
    let change = subsidy(1) - amount - fee;
    assert_eq!(tx.outs[1].value, change, "找零必须等于 输入 - 金额 - 手续费");
    assert_eq!(tx.outs[1].addr, k.addr, "找零必须回到付款方地址");

    let fees = c
        .validate_tx(&tx, &HashSet::new())
        .expect("钱包构造的交易必须通过链校验");
    assert_eq!(fees, fee, "validate_tx 返回的手续费必须等于输入减输出");
}

#[test]
fn send_omits_change_output_when_exact() {
    let (c, k) = chain_with_coins(b"send-exact");
    let to = Key::from_seed(b"exact-recipient", 0).addr;

    let tx = wallet::send(&c, &k, to, subsidy(1), 0, T1 + 1).expect("恰好花光时 send 必须成功");
    assert_eq!(tx.outs.len(), 1, "找零为 0 时不得产生空的找零输出");
    assert_eq!(tx.outs[0].value, subsidy(1), "输出金额必须等于输入总额");
    assert_eq!(tx.outs[0].addr, to, "全部金额付给收款地址");
    assert_eq!(
        c.validate_tx(&tx, &HashSet::new()).expect("必须通过校验"),
        0,
        "没有手续费时 validate_tx 应返回 0"
    );
}

#[test]
fn send_to_self_only_costs_fee() {
    let (mut c, k) = chain_with_coins(b"send-self");
    let miner = Key::from_seed(b"self-miner", 0);
    let before = c.balance(&k.addr);
    let fee = 7_000_u64;

    let tx = wallet::send(&c, &k, k.addr, COIN, fee, T1 + 1).expect("自转账必须成功");
    let sum: u64 = tx.outs.iter().map(|o| o.value).sum();
    assert_eq!(sum, before - fee, "输出总额必须等于输入总额减手续费");
    assert!(
        tx.outs.iter().all(|o| o.addr == k.addr),
        "自转账的所有输出都应回到自己地址"
    );

    mine_to(&mut c, miner.addr, &[tx], T1 + 1);
    assert_eq!(
        c.balance(&k.addr),
        before - fee,
        "自转账上链后余额只应减少手续费"
    );
    assert_eq!(
        c.balance(&miner.addr),
        subsidy(2) + fee,
        "矿工必须拿到出块补贴 + 手续费"
    );
}

#[test]
fn send_rejects_zero_amount_and_overflow() {
    let (c, k) = chain_with_coins(b"send-bad");
    let to = Key::from_seed(b"bad-recipient", 0).addr;

    let err = wallet::send(&c, &k, to, 0, 0, T1 + 1).expect_err("amount=0 必须被拒绝");
    assert!(
        err.contains("amount must be positive"),
        "amount=0 的错误信息应说明金额必须为正，实际: {err:?}"
    );

    let err = wallet::send(&c, &k, to, u64::MAX, 1, T1 + 1).expect_err("金额溢出必须被拒绝");
    assert!(
        err.contains("overflow"),
        "amount+fee 溢出时报错应提到 overflow，实际: {err:?}"
    );
}

#[test]
fn send_rejects_insufficient_funds() {
    let (c, k) = chain_with_coins(b"send-poor");
    let to = Key::from_seed(b"poor-recipient", 0).addr;
    let need = subsidy(1) + 1;

    let err = wallet::send(&c, &k, to, need, 0, T1 + 1).expect_err("余额不足必须被拒绝");
    assert_eq!(
        err,
        format!("insufficient funds: have {}, need {}", subsidy(1), need),
        "余额不足的错误信息必须给出实际余额与所需金额"
    );

    // 完全没有 utxo 的地址：余额为 0
    let empty = Key::from_seed(b"no-coins-at-all", 0);
    let err = wallet::send(&c, &empty, to, 1, 0, T1 + 1).expect_err("没有 utxo 时必须被拒绝");
    assert_eq!(
        err,
        "insufficient funds: have 0, need 1",
        "空钱包的错误信息必须显示 have 0"
    );

    // 金额够但手续费把余额顶爆：仍算余额不足
    let err = wallet::send(&c, &k, to, subsidy(1), 1, T1 + 1).expect_err("金额 + 手续费超额必须被拒绝");
    assert!(
        err.starts_with("insufficient funds: have "),
        "金额 + 手续费超额应报余额不足，实际: {err:?}"
    );
}

#[test]
fn send_uses_multiple_utxos_when_needed() {
    let k = Key::from_seed(b"multi-utxo", 0);
    let mut c = Chain::new(GENESIS_ADDR);
    mine_to(&mut c, k.addr, &[], T1);
    mine_to(&mut c, k.addr, &[], T1 + 1);

    let utxos = c.utxos_of(&k.addr);
    assert_eq!(utxos.len(), 2, "两次挖矿后应有 2 个 utxo");
    let expected: Vec<OutPoint> = utxos.iter().map(|(o, _)| *o).collect();

    let to = Key::from_seed(b"multi-recipient", 0).addr;
    let amount = subsidy(1) + 1; // 单个 coinbase 不够
    let tx = wallet::send(&c, &k, to, amount, 0, T1 + 2).expect("两个 utxo 必须够花");
    assert_eq!(tx.ins.len(), 2, "金额超过单个 utxo 时必须合并多个输入");
    let picked: Vec<OutPoint> = tx.ins.iter().map(|i| i.prev).collect();
    assert_eq!(
        picked, expected,
        "选币必须按 OutPoint 升序（与 utxos_of 的顺序一致），先入先出"
    );
    assert_eq!(c.validate_tx(&tx, &HashSet::new()).expect("必须通过校验"), 0);
}

#[test]
fn wallet_tx_enters_mempool_then_mines_and_clears() {
    let (mut c, k) = chain_with_coins(b"mempool-flow");
    let to = Key::from_seed(b"mem-recipient", 0).addr;
    let amount = 4 * COIN;
    let fee = 500_u64;

    let tx = wallet::send(&c, &k, to, amount, fee, T1 + 1).expect("send 必须成功");
    let mut m = Mempool::new();
    m.add(&c, tx.clone()).expect("钱包交易必须能进入内存池");
    assert_eq!(m.txs.len(), 1, "内存池中应有 1 笔交易");

    let picked = m.select(&c);
    assert_eq!(picked.len(), 1, "select 应返回这笔交易");
    let b = mine_to(&mut c, k.addr, &picked, T1 + 1);

    assert_eq!(c.balance(&to), amount, "收款方余额必须等于转账金额");
    assert_eq!(
        c.balance(&k.addr),
        2 * subsidy(1) - amount,
        "付款方余额 = 找零 + 新 coinbase（手续费回到自己）"
    );
    assert_eq!(
        b.txs[0].outs[0].value,
        subsidy(2) + fee,
        "coinbase 必须拿到出块补贴 + 交易手续费"
    );

    m.clean(&c);
    assert!(
        m.txs.is_empty(),
        "已上链的交易必须被 clean 从内存池移除（其输入已被花费）"
    );
}

#[test]
fn wallet_tx_without_signature_fails_validation() {
    let (c, k) = chain_with_coins(b"sig-check");
    let to = Key::from_seed(b"sig-recipient", 0).addr;
    let tx = wallet::send(&c, &k, to, COIN, 0, T1 + 1).expect("send 必须成功");
    assert_eq!(tx.ins[0].sig.len(), 64, "签名必须是 64 字节");
    assert_eq!(tx.ins[0].pk.len(), 33, "公钥必须是 33 字节");

    // 1) 完全不带签名
    let mut unsigned = tx.clone();
    unsigned.ins[0].sig.clear();
    unsigned.ins[0].pk.clear();
    let err = c
        .validate_tx(&unsigned, &HashSet::new())
        .expect_err("无签名的交易必须被拒绝");
    assert!(
        err.contains("pk") || err.contains("sig"),
        "无签名的交易应报 pk/sig 长度错误，实际: {err:?}"
    );

    // 2) 篡改输出金额 → 签名失效
    let mut tampered = tx.clone();
    tampered.outs[0].value += 1;
    let err = c
        .validate_tx(&tampered, &HashSet::new())
        .expect_err("被篡改的交易必须被拒绝");
    assert_eq!(err, "bad signature", "篡改输出后签名必须失效");

    // 3) 伪造他人公钥去花别人的 utxo
    let attacker = Key::from_seed(b"attacker", 0);
    let mut stolen = tx.clone();
    stolen.ins[0].pk = attacker.pk.to_vec();
    stolen.ins[0].sig = secp::sign(&attacker.sk, &stolen.signing_hash(0)).to_vec();
    let err = c
        .validate_tx(&stolen, &HashSet::new())
        .expect_err("花别人 utxo 的交易必须被拒绝");
    assert_eq!(err, "pk does not own utxo", "公钥与 utxo 归属不符必须被拒绝");
}
