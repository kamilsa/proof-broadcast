//! The `/proof-tree/1` request-response protocol.
//!
//! - `Hello { role, subnet }`: sent by both sides when a connection opens.
//!   An L2's tree node follows from its PeerId, so the role is all a peer
//!   needs to know what the other side aggregates.
//! - `Have { proofs }`: which chunks of which proofs we hold, pushed to the
//!   peers we serve (our fan-out) as chunks arrive, and to our sources once
//!   we complete a proof. Answered with `Interest`: the announced proofs the
//!   receiver will not fetch from us.
//! - `GetChunk { hash, index }`: answered with the chunk, `Missing`, or
//!   `Busy` when our fan-out for that proof is full.
//!
//! Frames are a little-endian `u32` length followed by bincode. The codec
//! counts every frame it reads or writes in a shared [`Traffic`].

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::StreamProtocol;
use serde::{Deserialize, Serialize};

use crate::assembly::ChunkBits;
use crate::proof::ProofId;

pub const PROTOCOL: StreamProtocol = StreamProtocol::new("/proof-tree/1");

/// Largest frame accepted (a chunk can be a whole proof with `chunk_count = 1`).
pub const MAX_FRAME: usize = 16 * 1024 * 1024;

/// Prover role.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
pub enum Role {
    /// Subnet prover: produces one proof and serves it.
    L1,
    /// Aggregator at the tree node its PeerId maps to.
    L2,
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::L1 => "l1",
            Self::L2 => "l2",
        })
    }
}

/// A proof, and which of its chunks the sender holds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Holding {
    pub id: ProofId,
    pub chunks: ChunkBits,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Request {
    Hello { role: Role, subnet: Option<u16> },
    Have { proofs: Vec<Holding> },
    GetChunk { hash: [u8; 32], index: u16 },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Response {
    Ack,
    /// Answer to `Have`: hashes of the announced proofs we will not fetch.
    Interest { unwanted: Vec<[u8; 32]> },
    Chunk { data: Vec<u8> },
    Missing,
    /// The holder already serves `fanout` peers for that proof.
    Busy,
}

impl Response {
    fn is_data(&self) -> bool {
        matches!(self, Self::Chunk { .. })
    }
}

/// Bytes on the wire (frame headers included), split into chunk payloads
/// (`data`) and everything else (`control`).
#[derive(Debug, Default)]
pub struct Traffic {
    pub tx_data: AtomicU64,
    pub tx_control: AtomicU64,
    pub rx_data: AtomicU64,
    pub rx_control: AtomicU64,
}

impl Traffic {
    pub fn tx(&self) -> u64 {
        self.tx_data.load(Ordering::Relaxed) + self.tx_control.load(Ordering::Relaxed)
    }

    pub fn rx(&self) -> u64 {
        self.rx_data.load(Ordering::Relaxed) + self.rx_control.load(Ordering::Relaxed)
    }

    fn add(counter: &AtomicU64, bytes: usize) {
        counter.fetch_add(bytes as u64, Ordering::Relaxed);
    }
}

#[derive(Clone, Default)]
pub struct TreeCodec {
    pub traffic: Arc<Traffic>,
}

async fn read_frame<T: AsyncRead + Unpin + Send>(io: &mut T) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    io.read_exact(&mut len).await?;
    let len = u32::from_le_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("frame of {len} bytes")));
    }
    let mut buf = vec![0u8; len];
    io.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn write_frame<T: AsyncWrite + Unpin + Send>(io: &mut T, payload: &[u8]) -> io::Result<()> {
    if payload.len() > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "frame too large"));
    }
    io.write_all(&(payload.len() as u32).to_le_bytes()).await?;
    io.write_all(payload).await?;
    io.flush().await
}

fn encode<M: Serialize>(message: &M) -> io::Result<Vec<u8>> {
    bincode::serialize(message).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
}

fn decode<M: for<'de> Deserialize<'de>>(bytes: &[u8]) -> io::Result<M> {
    bincode::deserialize(bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

impl libp2p::request_response::Codec for TreeCodec {
    type Protocol = StreamProtocol;
    type Request = Request;
    type Response = Response;

    async fn read_request<T>(&mut self, _: &StreamProtocol, io: &mut T) -> io::Result<Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let frame = read_frame(io).await?;
        Traffic::add(&self.traffic.rx_control, frame.len() + 4);
        decode(&frame)
    }

    async fn read_response<T>(&mut self, _: &StreamProtocol, io: &mut T) -> io::Result<Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let frame = read_frame(io).await?;
        let response: Response = decode(&frame)?;
        let counter = if response.is_data() {
            &self.traffic.rx_data
        } else {
            &self.traffic.rx_control
        };
        Traffic::add(counter, frame.len() + 4);
        Ok(response)
    }

    async fn write_request<T>(&mut self, _: &StreamProtocol, io: &mut T, req: Request) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let frame = encode(&req)?;
        write_frame(io, &frame).await?;
        Traffic::add(&self.traffic.tx_control, frame.len() + 4);
        Ok(())
    }

    async fn write_response<T>(&mut self, _: &StreamProtocol, io: &mut T, res: Response) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let frame = encode(&res)?;
        write_frame(io, &frame).await?;
        let counter = if res.is_data() {
            &self.traffic.tx_data
        } else {
            &self.traffic.tx_control
        };
        Traffic::add(counter, frame.len() + 4);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proof::make_proof;
    use futures::executor::block_on;
    use futures::io::Cursor;
    use libp2p::request_response::Codec;

    #[test]
    fn requests_and_responses_round_trip_and_are_counted() {
        let proof = make_proof(1, 1000);
        let id = ProofId::for_proof(3, 1, &proof, 8);
        let mut codec = TreeCodec::default();
        let requests = [
            Request::Hello { role: Role::L1, subnet: Some(3) },
            Request::Have {
                proofs: vec![Holding { id, chunks: ChunkBits::full(8) }],
            },
            Request::GetChunk { hash: id.hash, index: 7 },
        ];
        for req in requests {
            let mut wire = Cursor::new(Vec::new());
            block_on(codec.write_request(&PROTOCOL, &mut wire, req.clone())).unwrap();
            wire.set_position(0);
            assert_eq!(block_on(codec.read_request(&PROTOCOL, &mut wire)).unwrap(), req);
        }
        for res in [Response::Ack, Response::Interest { unwanted: vec![id.hash] }, Response::Busy] {
            let mut wire = Cursor::new(Vec::new());
            block_on(codec.write_response(&PROTOCOL, &mut wire, res.clone())).unwrap();
            wire.set_position(0);
            assert_eq!(block_on(codec.read_response(&PROTOCOL, &mut wire)).unwrap(), res);
        }
        let mut wire = Cursor::new(Vec::new());
        let chunk = Response::Chunk { data: vec![9; 125] };
        block_on(codec.write_response(&PROTOCOL, &mut wire, chunk.clone())).unwrap();
        let chunk_frame = wire.get_ref().len() as u64;
        wire.set_position(0);
        assert_eq!(block_on(codec.read_response(&PROTOCOL, &mut wire)).unwrap(), chunk);
        let t = &codec.traffic;
        assert_eq!(t.tx_data.load(Ordering::Relaxed), chunk_frame);
        assert_eq!(t.rx_data.load(Ordering::Relaxed), chunk_frame);
        assert!(t.tx_control.load(Ordering::Relaxed) > 0);
        assert_eq!(t.tx(), t.rx());
    }

    #[test]
    fn oversized_frames_are_rejected() {
        let mut wire = Cursor::new(((MAX_FRAME + 1) as u32).to_le_bytes().to_vec());
        let mut codec = TreeCodec::default();
        assert!(block_on(codec.read_request(&PROTOCOL, &mut wire)).is_err());
        let mut wire = Cursor::new(vec![3, 0, 0, 0, 0xff, 0xff, 0xff]);
        assert!(block_on(codec.read_request(&PROTOCOL, &mut wire)).is_err());
    }
}
