//! 密码学与编码原语测试 —— SPEC §1（codec）、§2（hash）、§3（secp）与 §10 tests/crypto.rs。
//!
//! 全部断言使用公开标准向量或往返性质，不依赖网络与外部文件。

use blockchain::codec::{
    b58check, hex, put_bytes, put_hash, put_i64, put_u16, put_u32, put_u64, put_u8, unb58check,
    unhex, Rd,
};
use blockchain::hash::{h160, merkle, sha256, sha256d};
use blockchain::secp;

/// SHA-256("")，FIPS 180-4 标准向量
const SHA_EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
/// SHA-256("abc")
const SHA_ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
/// SHA-256("hello")
const SHA_HELLO: &str = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
/// sha256d("abc")
const SHA256D_ABC: &str = "4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358";
/// secp256k1 生成点的压缩公钥（私钥 = 1）
const G_PUBKEY: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
/// merkle(sha256d("L1"), sha256d("L2"), sha256d("L3"))
const MERKLE_3: &str = "21866bbe54e9dd2b626df8d081e8ad4b9923f9e185b4e8622b3809433eec9a58";
/// 三叶子用例中「奇数复制末尾」后的右子树：sha256d(leaf3 || leaf3)
const MERKLE_NODE_22: &str = "e2f2c2a4508e4a7aeadc522dea4dc06af56ed3fabd6193b7ec89121211e050fc";

const BASE58_ALPHABET: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// 私钥 1（32 字节大端）
fn sk_one() -> [u8; 32] {
    let mut sk = [0u8; 32];
    sk[31] = 1;
    sk
}

fn leaf(s: &str) -> [u8; 32] {
    sha256d(s.as_bytes())
}

#[test]
fn sha256_known_vectors() {
    assert_eq!(hex(&sha256(b"")), SHA_EMPTY, "SHA-256 空串向量不符（FIPS 180-4）");
    assert_eq!(hex(&sha256(b"abc")), SHA_ABC, "SHA-256(\"abc\") 向量不符");
    assert_eq!(hex(&sha256(b"hello")), SHA_HELLO, "SHA-256(\"hello\") 向量不符");
    // 跨块边界：1000 个 'a'
    assert_eq!(
        hex(&sha256(&[b'a'; 1000])),
        "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3",
        "SHA-256 多块输入向量不符"
    );
}

#[test]
fn sha256d_is_double_sha256() {
    assert_eq!(hex(&sha256d(b"abc")), SHA256D_ABC, "sha256d(\"abc\") 向量不符");
    for m in [&b""[..], &b"abc"[..], &b"ATL-Chain"[..]] {
        assert_eq!(sha256d(m), sha256(&sha256(m)), "sha256d 必须等于 sha256(sha256(x))");
    }
}

#[test]
fn h160_is_truncated_sha256() {
    let d = b"ATL-Chain address digest";
    let full = sha256(d);
    let mut want = [0u8; 20];
    want.copy_from_slice(&full[..20]);
    assert_eq!(h160(d), want, "h160 必须是 sha256(d)[0..20]（SPEC 为省行数不实现 RIPEMD160）");
    let pk = secp::pubkey(&sk_one());
    assert_eq!(secp::addr(&pk), h160(&pk), "addr() 必须等于 h160(pk)");
}

#[test]
fn merkle_three_leaves_matches_manual_tree() {
    let (a, b, c) = (leaf("L1"), leaf("L2"), leaf("L3"));
    assert_eq!(
        hex(&a),
        "3cdeab931a0aee1649ad0995d4ec25e0606fd19a35eec08c4e624d7ef12d785b",
        "leaf1 向量不符"
    );
    assert_eq!(
        hex(&b),
        "1342cbe0676f7b6f177303bcba204bfc47a2b256b57221dae685725d33f2668b",
        "leaf2 向量不符"
    );
    assert_eq!(
        hex(&c),
        "93c3539f09faa3d704d99f2c5c83c2fee5e7c29422f2443788e5729cc0a0d2ae",
        "leaf3 向量不符"
    );

    // 手工二叉树：node01 = sha256d(a||b)，node22 = sha256d(c||c)（奇数复制末尾），root = sha256d(node01||node22)
    let mut ab = a.to_vec();
    ab.extend_from_slice(&b);
    let node01 = sha256d(&ab);
    let mut cc = c.to_vec();
    cc.extend_from_slice(&c);
    let node22 = sha256d(&cc);
    assert_eq!(hex(&node22), MERKLE_NODE_22, "奇数复制末尾后的右子树向量不符");

    let mut root_in = node01.to_vec();
    root_in.extend_from_slice(&node22);
    assert_eq!(merkle(&[a, b, c]), sha256d(&root_in), "三叶子 merkle 根必须等于手工构造值");
    assert_eq!(hex(&merkle(&[a, b, c])), MERKLE_3, "三叶子 merkle 根向量不符");
    // 奇数复制末尾等价于显式重复最后一个叶子
    assert_eq!(merkle(&[a, b, c]), merkle(&[a, b, c, c]), "奇数复制末尾必须等价于显式重复");
}

#[test]
fn merkle_empty_and_single_leaf() {
    assert_eq!(merkle(&[]), [0u8; 32], "空集合的 merkle 根必须是全 0");
    let a = leaf("only");
    assert_eq!(merkle(&[a]), a, "单叶子 merkle 根必须等于该叶子（叶子已经是 txid，不再哈希）");
    let b = leaf("second");
    let mut ab = a.to_vec();
    ab.extend_from_slice(&b);
    assert_eq!(merkle(&[a, b]), sha256d(&ab), "两叶子 merkle 根必须是 sha256d(a||b)");
}

#[test]
fn base58check_roundtrip_and_checksum() {
    let payload = b"ATL-Chain payload";
    let s = b58check(payload);
    assert!(!s.is_empty(), "b58check 结果不能为空");
    assert!(
        s.chars().all(|c| BASE58_ALPHABET.contains(c)),
        "Base58Check 只能包含 Base58 字母表字符，实际为 {s}"
    );
    assert_eq!(unb58check(&s).as_deref(), Some(&payload[..]), "Base58Check 必须可往返");

    // 空 payload 也要可往返
    assert_eq!(unb58check(&b58check(b"")).as_deref(), Some(&b""[..]), "空 payload 必须可往返");

    // 篡改最后一个字符 -> 校验和失败
    let mut chars: Vec<char> = s.chars().collect();
    let last = chars.len() - 1;
    chars[last] = if chars[last] == '1' { '2' } else { '1' };
    let tampered: String = chars.into_iter().collect();
    assert!(unb58check(&tampered).is_none(), "篡改字符后 Base58Check 必须校验失败");

    // 非 Base58 字符（0、O、I、l 不在字母表内）
    assert!(unb58check("0OIl").is_none(), "含非 Base58 字符必须解码失败");
    assert!(unb58check("1").is_none(), "过短的 Base58Check 必须解码失败");
}

#[test]
fn secp_pubkey_of_one_is_generator_point() {
    let pk = secp::pubkey(&sk_one());
    assert_eq!(hex(&pk), G_PUBKEY, "私钥 1 的压缩公钥必须是 secp256k1 生成点");
    assert!(pk[0] == 2 || pk[0] == 3, "压缩公钥首字节必须是 02 或 03，实际 {}", pk[0]);
}

#[test]
fn secp_sign_verify_and_tamper() {
    let sk = sk_one();
    let pk = secp::pubkey(&sk);
    let msg = sha256(b"ATL-Chain signature test");
    let sig = secp::sign(&sk, &msg);

    assert_eq!(sig.len(), 64, "签名必须是 64 字节 r||s");
    assert_ne!(sig, [0u8; 64], "签名不能是零值");
    assert!(secp::verify(&pk, &msg, &sig), "自签必须验签通过");

    // 篡改 r 的任一字节
    let mut bad_r = sig;
    bad_r[0] ^= 0x01;
    assert!(!secp::verify(&pk, &msg, &bad_r), "篡改签名 r 后必须验签失败");
    // 篡改 s 的任一字节
    let mut bad_s = sig;
    bad_s[63] ^= 0x01;
    assert!(!secp::verify(&pk, &msg, &bad_s), "篡改签名 s 后必须验签失败");
    // 篡改消息
    let mut bad_msg = msg;
    bad_msg[0] ^= 0x01;
    assert!(!secp::verify(&pk, &bad_msg, &sig), "篡改消息后必须验签失败");
    // 用别人的公钥验证
    let mut sk2 = [0u8; 32];
    sk2[31] = 2;
    let pk2 = secp::pubkey(&sk2);
    assert!(!secp::verify(&pk2, &msg, &sig), "用错误公钥必须验签失败");
    // 全零签名
    assert!(!secp::verify(&pk, &msg, &[0u8; 64]), "全零签名必须验签失败");
    // 非法压缩公钥前缀
    let mut bad_pk = pk;
    bad_pk[0] = 0x04;
    assert!(!secp::verify(&bad_pk, &msg, &sig), "非法公钥前缀必须验签失败");
}

#[test]
fn secp_sign_is_deterministic() {
    let sk = sk_one();
    let msg = sha256(b"deterministic-nonce");
    assert_eq!(
        secp::sign(&sk, &msg),
        secp::sign(&sk, &msg),
        "同一 (sk, msg) 的签名必须确定（确定性 nonce）"
    );
    assert_ne!(
        secp::sign(&sk, &msg),
        secp::sign(&sk, &sha256(b"other")),
        "不同消息的签名必须不同"
    );
}

#[test]
fn codec_rd_roundtrip() {
    let mut b = Vec::new();
    put_u8(&mut b, 0xab);
    put_u16(&mut b, 0x1234);
    put_u32(&mut b, 0xdead_beef);
    put_u64(&mut b, 0x0102_0304_0506_0708);
    put_i64(&mut b, -2);
    put_bytes(&mut b, b"ATL");
    put_hash(&mut b, &[7u8; 32]);

    let mut r = Rd::new(&b);
    assert_eq!(r.u8(), Some(0xab));
    assert_eq!(r.u16(), Some(0x1234), "u16 必须按小端读取");
    assert_eq!(r.u32(), Some(0xdead_beef), "u32 必须按小端读取");
    assert_eq!(r.u64(), Some(0x0102_0304_0506_0708), "u64 必须按小端读取");
    assert_eq!(r.i64(), Some(-2), "i64 必须按小端读取");
    assert_eq!(r.bytes(), Some(&b"ATL"[..]), "u32 长度前缀字节串往返失败");
    assert_eq!(r.hash(), Some([7u8; 32]));
    assert_eq!(r.rest(), 0, "读完后剩余字节应为 0");
    assert_eq!(r.u8(), None, "游标耗尽后必须返回 None");

    // 越界与截断一律 None
    let short: &[u8] = &[3, 0, 0, 0, b'a'];
    assert_eq!(Rd::new(short).bytes(), None, "长度前缀声明的长度越界时必须返回 None");
    assert_eq!(Rd::new(&b[..3]).u32(), None, "不足 4 字节时 u32 必须返回 None");
    let mut r2 = Rd::new(&b);
    assert_eq!(r2.raw(b.len() + 1), None, "raw 越界必须返回 None");
}

#[test]
fn hex_unhex_roundtrip() {
    let data: Vec<u8> = (0u8..=255).collect();
    let h = hex(&data);
    assert_eq!(h.len(), 512, "hex 输出长度应为字节数的 2 倍");
    assert!(
        h.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
        "hex 必须输出小写"
    );
    assert_eq!(unhex(&h), Some(data.clone()), "hex/unhex 必须可往返");
    assert_eq!(unhex("abc"), None, "奇数长度 hex 必须返回 None");
    assert_eq!(unhex("zz"), None, "非法 hex 字符必须返回 None");
    assert_eq!(unhex("00ff"), Some(vec![0x00, 0xff]));
}
