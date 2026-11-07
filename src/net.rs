//! P2P 帧协议：`MAGIC("ATL1") || u32 len || payload`，payload 首字节为消息类型码。
use crate::chain::{Block, Tx, MAX_FRAME};
use crate::codec::{put_u16, put_u32, put_u64, Rd};
use std::io::{Error, ErrorKind::InvalidData, Read, Result, Write};
use std::net::TcpStream;

pub const MAGIC: [u8; 4] = *b"ATL1";

#[derive(Clone, Debug)]
pub enum Msg {
    Version { height: u64, port: u16 },  // 0x01
    GetBlocks { from: u64 },             // 0x02
    Blocks(Vec<Block>),                  // 0x03
    Tx(Tx),                              // 0x04
    Ping,                                // 0x05
    Pong,                                // 0x06
}

impl Msg {
    pub fn enc(&self) -> Vec<u8> {
        let mut b = Vec::new();
        match self {
            Msg::Version { height, port } => { b.push(1); put_u64(&mut b, *height); put_u16(&mut b, *port) }
            Msg::GetBlocks { from } => { b.push(2); put_u64(&mut b, *from) }
            Msg::Blocks(bs) => {
                b.push(3);
                put_u32(&mut b, bs.len() as u32);
                for x in bs { b.extend_from_slice(&x.enc()) }  // Block::dec 自定界，无需长度前缀
            }
            Msg::Tx(t) => { b.push(4); b.extend_from_slice(&t.enc()) }
            Msg::Ping => b.push(5),
            Msg::Pong => b.push(6),
        }
        b
    }

    pub fn dec(d: &[u8]) -> Option<Msg> {
        let mut r = Rd::new(d);
        let m = match r.u8()? {
            1 => Msg::Version { height: r.u64()?, port: r.u16()? },
            2 => Msg::GetBlocks { from: r.u64()? },
            3 => {
                let n = r.u32()? as usize;
                if n > r.rest() { return None }  // 每块至少 1 字节，先挡住恶意的大 n
                let mut v = Vec::new();
                for _ in 0..n { v.push(Block::dec(&mut r)?) }
                Msg::Blocks(v)
            }
            4 => Msg::Tx(Tx::dec(&mut r)?),
            5 => Msg::Ping,
            6 => Msg::Pong,
            _ => return None,
        };
        Some(m)
    }
}

/// 完整帧（MAGIC + 长度 + payload）；超长返回 Err。
pub fn frame(m: &Msg) -> Result<Vec<u8>> {
    let p = m.enc();
    if p.len() > MAX_FRAME { return Err(Error::new(InvalidData, "frame too large")) }
    let mut b = Vec::with_capacity(p.len() + 8);
    b.extend_from_slice(&MAGIC);
    put_u32(&mut b, p.len() as u32);
    b.extend_from_slice(&p);
    Ok(b)
}

pub fn send(s: &mut TcpStream, m: &Msg) -> Result<()> {
    s.write_all(&frame(m)?)?;
    s.flush()
}

/// 读满 b，返回实际字节数（0 表示对端在帧边界处 EOF）。
fn need(s: &mut TcpStream, b: &mut [u8]) -> Result<usize> {
    let mut n = 0;
    while n < b.len() {
        match s.read(&mut b[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

/// EOF -> Ok(None)；坏 magic / 超长 / 坏 payload -> Err。
pub fn recv(s: &mut TcpStream) -> Result<Option<Msg>> {
    let mut h = [0u8; 8];
    match need(s, &mut h)? {
        0 => return Ok(None),
        8 => {}
        _ => return Err(Error::new(std::io::ErrorKind::UnexpectedEof, "short frame header")),
    }
    if h[..4] != MAGIC { return Err(Error::new(InvalidData, "bad magic")) }
    let len = u32::from_le_bytes([h[4], h[5], h[6], h[7]]) as usize;
    if len > MAX_FRAME { return Err(Error::new(InvalidData, "frame too large")) }
    let mut p = vec![0u8; len];
    if need(s, &mut p)? != len {
        return Err(Error::new(std::io::ErrorKind::UnexpectedEof, "short frame body"));
    }
    Msg::dec(&p).map(Some).ok_or_else(|| Error::new(InvalidData, "bad frame payload"))
}
