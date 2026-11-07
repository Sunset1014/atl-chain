//! P2P 帧协议测试 —— SPEC §7 与 §10 tests/net.rs。
//!
//! 只连 127.0.0.1（`TcpListener` + `TcpStream`），不访问外网。

use blockchain::chain::{Block, OutPoint, Tx, TxIn, TxOut, MAX_FRAME};
use blockchain::net::{self, Msg};
use std::io::Write;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

/// 读超时：任何一步卡住都要在 10 秒内失败而不是永久挂起。
const WAIT: Duration = Duration::from_secs(10);

fn sample_tx() -> Tx {
    Tx {
        time: 1_700_000_123,
        ins: vec![TxIn { prev: OutPoint { txid: [1u8; 32], idx: 3 }, sig: vec![0xaa; 64], pk: vec![0x02; 33] }],
        outs: vec![TxOut { value: 1234, addr: [7u8; 20] }, TxOut { value: 5678, addr: [8u8; 20] }],
    }
}

fn sample_block(nonce: u32) -> Block {
    Block { prev: [2u8; 32], time: 1_700_000_222, bits: 0x1f0f_ffff, nonce, txs: vec![sample_tx()] }
}

/// 在 127.0.0.1:0 上监听，接受一条连接后执行回调；返回地址与线程句柄。
fn serve<F>(f: F) -> (SocketAddr, thread::JoinHandle<()>)
where
    F: FnOnce(TcpStream) + Send + 'static,
{
    let l = TcpListener::bind("127.0.0.1:0").expect("绑定 127.0.0.1:0 失败");
    let addr = l.local_addr().expect("取本地地址失败");
    let h = thread::spawn(move || {
        let (s, _) = l.accept().expect("accept 失败");
        s.set_read_timeout(Some(WAIT)).expect("设置读超时失败");
        f(s);
    });
    (addr, h)
}

fn connect(addr: SocketAddr) -> TcpStream {
    let c = TcpStream::connect(addr).expect("连接本地服务器失败");
    c.set_read_timeout(Some(WAIT)).expect("设置读超时失败");
    c
}

#[test]
fn msg_roundtrip_all_variants() {
    let cases = vec![
        Msg::Version { height: 7, port: 8333 },
        Msg::GetBlocks { from: 0 },
        Msg::GetBlocks { from: u64::MAX },
        Msg::Blocks(vec![]),
        Msg::Blocks(vec![sample_block(1), sample_block(2)]),
        Msg::Tx(sample_tx()),
        Msg::Ping,
        Msg::Pong,
    ];
    for m in cases {
        let enc = m.enc();
        let dec = Msg::dec(&enc).unwrap_or_else(|| panic!("解码失败: {m:?}"));
        assert_eq!(dec.enc(), enc, "重新编码必须与原始字节完全一致: {m:?}");
    }

    // 消息类型码（SPEC §7）
    assert_eq!(Msg::Version { height: 1, port: 2 }.enc()[0], 1, "Version = 0x01");
    assert_eq!(Msg::GetBlocks { from: 1 }.enc()[0], 2, "GetBlocks = 0x02");
    assert_eq!(Msg::Blocks(vec![]).enc()[0], 3, "Blocks = 0x03");
    assert_eq!(Msg::Tx(sample_tx()).enc()[0], 4, "Tx = 0x04");
    assert_eq!(Msg::Ping.enc(), vec![5u8], "Ping = 0x05 且无负载");
    assert_eq!(Msg::Pong.enc(), vec![6u8], "Pong = 0x06 且无负载");

    // 变体判别与字段值
    match Msg::dec(&Msg::Version { height: 42, port: 9000 }.enc()).unwrap() {
        Msg::Version { height, port } => {
            assert_eq!(height, 42, "Version.height");
            assert_eq!(port, 9000, "Version.port");
        }
        other => panic!("期望 Version，得到 {other:?}"),
    }
    match Msg::dec(&Msg::GetBlocks { from: 99 }.enc()).unwrap() {
        Msg::GetBlocks { from } => assert_eq!(from, 99, "GetBlocks.from"),
        other => panic!("期望 GetBlocks，得到 {other:?}"),
    }
    match Msg::dec(&Msg::Blocks(vec![sample_block(7)]).enc()).unwrap() {
        Msg::Blocks(bs) => {
            assert_eq!(bs.len(), 1, "Blocks 内的区块数");
            assert_eq!(bs[0].nonce, 7, "区块 nonce 往返失败");
            assert_eq!(bs[0].txs[0].id(), sample_tx().id(), "区块内交易往返失败");
        }
        other => panic!("期望 Blocks，得到 {other:?}"),
    }
    match Msg::dec(&Msg::Tx(sample_tx()).enc()).unwrap() {
        Msg::Tx(tx) => assert_eq!(tx.id(), sample_tx().id(), "Tx 往返失败"),
        other => panic!("期望 Tx，得到 {other:?}"),
    }
    assert!(matches!(Msg::dec(&Msg::Ping.enc()).unwrap(), Msg::Ping), "Ping 变体判别失败");
    assert!(matches!(Msg::dec(&Msg::Pong.enc()).unwrap(), Msg::Pong), "Pong 变体判别失败");
}

#[test]
fn msg_dec_rejects_garbage() {
    assert!(Msg::dec(&[]).is_none(), "空 payload 必须解码失败");
    assert!(Msg::dec(&[0]).is_none(), "未知类型码 0x00 必须解码失败");
    assert!(Msg::dec(&[7]).is_none(), "未知类型码 0x07 必须解码失败");
    assert!(Msg::dec(&[255]).is_none(), "未知类型码 0xff 必须解码失败");
    // Version 需要 1 + 8 + 2 = 11 字节
    assert!(Msg::dec(&[1, 0, 0, 0, 0, 0, 0, 0, 0]).is_none(), "截断的 Version 必须解码失败");
    // GetBlocks 需要 1 + 8 字节
    assert!(Msg::dec(&[2, 0, 0, 0]).is_none(), "截断的 GetBlocks 必须解码失败");
    // Blocks 的数量头远大于剩余字节
    assert!(Msg::dec(&[3, 255, 255, 255, 255]).is_none(), "Blocks 数量越界必须解码失败");
    assert!(Msg::dec(&[3, 1, 0, 0, 0]).is_none(), "Blocks 缺少区块数据必须解码失败");
    // Tx 长度前缀越界
    assert!(Msg::dec(&[4, 16, 0, 0, 0, b'x']).is_none(), "Tx 长度前缀越界必须解码失败");
}

#[test]
fn frame_layout_matches_spec() {
    let f = net::frame(&Msg::Ping).expect("frame 应成功");
    assert_eq!(&f[..4], b"ATL1", "帧头必须是 MAGIC \"ATL1\"");
    assert_eq!(f.len(), 9, "Ping 帧应为 4(MAGIC) + 4(len) + 1(payload) 字节");
    assert_eq!(&f[4..8], &1u32.to_le_bytes(), "长度字段必须是 payload 长度的小端 u32");
    assert_eq!(f[8], 5, "Ping 的 payload 类型码必须是 0x05");

    let tx = net::frame(&Msg::Tx(sample_tx())).expect("Tx 帧应成功");
    assert_eq!(&tx[4..8], &((tx.len() - 8) as u32).to_le_bytes(), "Tx 帧长度字段不等于 payload 长度");
    assert_eq!(tx[8], 4, "Tx 的 payload 类型码必须是 0x04");
    assert!(tx.len() <= MAX_FRAME + 8, "正常帧长度不应超过 MAX_FRAME + 8");
}

#[test]
fn tcp_send_recv_roundtrip() {
    let (addr, h) = serve(|mut s| {
        let m = net::recv(&mut s).expect("服务器读失败").expect("服务器期望收到消息");
        match m {
            Msg::GetBlocks { from } => assert_eq!(from, 5, "服务器收到的 GetBlocks.from"),
            other => panic!("服务器期望 GetBlocks，得到 {other:?}"),
        }
        net::send(&mut s, &Msg::Version { height: 9, port: 1234 }).expect("服务器发送 Version 失败");
        net::send(&mut s, &Msg::Blocks(vec![sample_block(1), sample_block(2)])).expect("服务器发送 Blocks 失败");
        // 对端 close 之后必须返回 Ok(None) 而不是 Err
        let eof = net::recv(&mut s).expect("对端关闭时 recv 不应返回 Err");
        assert!(eof.is_none(), "对端关闭后 recv 必须返回 Ok(None)，得到 {eof:?}");
    });

    let mut c = connect(addr);
    net::send(&mut c, &Msg::GetBlocks { from: 5 }).expect("客户端发送失败");
    match net::recv(&mut c).expect("客户端读失败").expect("客户端期望 Version") {
        Msg::Version { height, port } => {
            assert_eq!(height, 9, "Version.height 往返失败");
            assert_eq!(port, 1234, "Version.port 往返失败");
        }
        other => panic!("客户端期望 Version，得到 {other:?}"),
    }
    match net::recv(&mut c).expect("客户端读 Blocks 失败").expect("客户端期望 Blocks") {
        Msg::Blocks(bs) => {
            assert_eq!(bs.len(), 2, "Blocks 往返数量");
            assert_eq!(bs[0].nonce, 1, "第一个区块 nonce");
            assert_eq!(bs[1].nonce, 2, "第二个区块 nonce");
            assert_eq!(bs[0].txs[0].id(), sample_tx().id(), "区块内交易往返失败");
        }
        other => panic!("客户端期望 Blocks，得到 {other:?}"),
    }
    drop(c);
    h.join().expect("服务器线程 panic");
}

#[test]
fn recv_returns_none_on_eof() {
    let (addr, h) = serve(|_s| {
        // 什么都不发，直接关闭
    });
    let mut c = connect(addr);
    let m = net::recv(&mut c).expect("对端 EOF 时 recv 必须返回 Ok(None)，不能返回 Err");
    assert!(m.is_none(), "没有数据时 recv 必须返回 Ok(None)");
    h.join().expect("服务器线程 panic");
}

#[test]
fn recv_rejects_oversize_length_header() {
    let (addr, h) = serve(|mut s| {
        let mut b = Vec::new();
        b.extend_from_slice(&net::MAGIC);
        b.extend_from_slice(&((MAX_FRAME as u32) + 1).to_le_bytes());
        s.write_all(&b).expect("写超长长度头失败");
        s.flush().ok();
        thread::sleep(Duration::from_millis(50));
    });
    let mut c = connect(addr);
    let e = net::recv(&mut c).expect_err("超过 MAX_FRAME 的长度头必须返回 Err");
    assert!(!e.to_string().is_empty(), "超长帧错误应有可读信息");
    h.join().expect("服务器线程 panic");
}

#[test]
fn recv_rejects_bad_magic() {
    let (addr, h) = serve(|mut s| {
        let mut b = Vec::new();
        b.extend_from_slice(b"XXXX");
        b.extend_from_slice(&1u32.to_le_bytes());
        b.push(5);
        s.write_all(&b).expect("写坏 magic 帧失败");
        s.flush().ok();
        thread::sleep(Duration::from_millis(50));
    });
    let mut c = connect(addr);
    assert!(net::recv(&mut c).is_err(), "坏 MAGIC 必须返回 Err");
    h.join().expect("服务器线程 panic");
}

#[test]
fn recv_rejects_truncated_body() {
    let (addr, h) = serve(|mut s| {
        let mut b = Vec::new();
        b.extend_from_slice(&net::MAGIC);
        b.extend_from_slice(&10u32.to_le_bytes()); // 声明 10 字节，只给 3 字节
        b.extend_from_slice(&[1, 2, 3]);
        s.write_all(&b).expect("写截断帧失败");
        s.flush().ok();
        // 关闭连接，让对端读 body 时遇到 EOF
    });
    let mut c = connect(addr);
    assert!(net::recv(&mut c).is_err(), "声明长度与实际字节不足时必须返回 Err");
    h.join().expect("服务器线程 panic");
}

#[test]
fn recv_rejects_bad_payload_type() {
    let (addr, h) = serve(|mut s| {
        let mut b = Vec::new();
        b.extend_from_slice(&net::MAGIC);
        b.extend_from_slice(&1u32.to_le_bytes());
        b.push(99); // 未知类型码
        s.write_all(&b).expect("写坏 payload 帧失败");
        s.flush().ok();
        thread::sleep(Duration::from_millis(50));
    });
    let mut c = connect(addr);
    assert!(net::recv(&mut c).is_err(), "未知消息类型码必须返回 Err");
    h.join().expect("服务器线程 panic");
}

#[test]
fn ping_pong_roundtrip_over_tcp() {
    let (addr, h) = serve(|mut s| {
        for _ in 0..3 {
            match net::recv(&mut s).expect("服务器读失败").expect("服务器期望 Ping") {
                Msg::Ping => net::send(&mut s, &Msg::Pong).expect("服务器发送 Pong 失败"),
                other => panic!("服务器期望 Ping，得到 {other:?}"),
            }
        }
    });
    let mut c = connect(addr);
    for i in 0..3 {
        net::send(&mut c, &Msg::Ping).expect("客户端发送 Ping 失败");
        match net::recv(&mut c).expect("客户端读失败").expect("客户端期望 Pong") {
            Msg::Pong => {}
            other => panic!("第 {i} 轮期望 Pong，得到 {other:?}"),
        }
    }
    drop(c);
    h.join().expect("服务器线程 panic");
}
