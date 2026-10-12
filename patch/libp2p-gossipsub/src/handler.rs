// Copyright 2020 Sigma Prime Pty Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

use std::{
    pin::Pin,
    task::{Context, Poll},
    time::{SystemTime, UNIX_EPOCH},
};

use asynchronous_codec::Framed;
use futures::{StreamExt, future::Either, prelude::*};
use libp2p_core::{PeerId, upgrade::DeniedUpgrade};
use libp2p_swarm::{
    Stream,
    handler::{
        ConnectionEvent, ConnectionHandler, ConnectionHandlerEvent, DialUpgradeError,
        FullyNegotiatedInbound, FullyNegotiatedOutbound, StreamUpgradeError, SubstreamProtocol,
    },
};
use sha2::{Digest, Sha256};
use web_time::Instant;

use crate::{
    ValidationError,
    protocol::{GossipsubCodec, ProtocolConfig},
    queue::Queue,
    rpc_proto::proto,
    types::{PeerKind, RawMessage, RpcIn, RpcOut},
};

/// The event emitted by the Handler. This informs the behaviour of various events created
/// by the handler.
#[derive(Debug)]
pub enum HandlerEvent {
    /// A GossipsubRPC message has been received. This also contains a list of invalid messages (if
    /// any) that were received.
    Message {
        /// The GossipsubRPC message excluding any invalid messages.
        rpc: RpcIn,
        /// Any invalid messages that were received in the RPC, along with the associated
        /// validation error.
        invalid_messages: Vec<(RawMessage, ValidationError)>,
    },
    /// An inbound or outbound substream has been established with the peer and this informs over
    /// which protocol. This message only occurs once per connection.
    PeerKind(PeerKind),
    /// A message to be published was dropped because it could not be sent in time.
    MessageDropped(RpcOut),
}

/// A message sent from the behaviour to the handler.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum HandlerIn {
    /// The peer has joined the mesh.
    JoinedMesh,
    /// The peer has left the mesh.
    LeftMesh,
}

/// The maximum number of inbound or outbound substreams attempts we allow.
///
/// Gossipsub is supposed to have a single long-lived inbound and outbound substream. On failure we
/// attempt to recreate these. This imposes an upper bound of new substreams before we consider the
/// connection faulty and disable the handler. This also prevents against potential substream
/// creation loops.
const MAX_SUBSTREAM_ATTEMPTS: usize = 5;

// Record stream writes/reads, including duplicates which do not reach
// the application's Gossipsub event handler. Hash the complete logical body so
// two different partials of one group cannot be confused.
//
// proof-broadcast: tag `/proofs/1` traffic with the proof it carries. A whole
// proof message is bincode `ProofMessage { subnet: u16, prover: u16,
// committees: u64, .. }`; a partial's group id is `0x03 || subnet u16 ||
// prover u16 || committees u64 || ..` (all LE). `subnet=65535` marks an L2's
// intermediate aggregate, `mask=` is its committee bitmask. Partials also
// report `body=` (chunk bytes; 0 = metadata-only announcement). On
// `/proofs_chunked/1` and `/proofs_chunked_pull/1` each message is one bincode
// `ChunkMessage { subnet, prover, committees, index: u16, .. }`, tagged with
// `index=` too; `/proofs_headers/1` carries `HeaderMessage { subnet, prover,
// committees, .. }`. WANT control messages (pull-gated topics) are traced as
// `want=1` with the proof of the group they ask for.
const PROOFS_TOPIC: &str = "/proofs/1";
const PROOFS_HEADERS_TOPIC: &str = "/proofs_headers/1";
const PROOFS_CHUNKED_TOPIC: &str = "/proofs_chunked/1";
const PROOFS_CHUNKED_PULL_TOPIC: &str = "/proofs_chunked_pull/1";

fn proof_fields(b: &[u8]) -> String {
    format!(
        " subnet={} prover={} mask={}",
        u16::from_le_bytes([b[0], b[1]]),
        u16::from_le_bytes([b[2], b[3]]),
        u64::from_le_bytes(b[4..12].try_into().expect("8 bytes"))
    )
}

fn proof_tag(topic: &str, head: &[u8]) -> String {
    match topic {
        PROOFS_TOPIC | PROOFS_HEADERS_TOPIC => head.get(..12).map(proof_fields).unwrap_or_default(),
        PROOFS_CHUNKED_TOPIC | PROOFS_CHUNKED_PULL_TOPIC => head
            .get(..14)
            .map(|b| format!("{} index={}", proof_fields(b), u16::from_le_bytes([b[12], b[13]])))
            .unwrap_or_default(),
        _ => String::new(),
    }
}

fn group_tag(topic: &str, group_id: &[u8]) -> String {
    proof_tag(topic, group_id.get(1..).unwrap_or_default())
}

/// One `wire_*` line per group a WANT asks for. The id hashes the topic and
/// group, so a send and its receive match.
fn trace_want(direction: &str, now_us: u128, peer: PeerId, topic: &str, groups: &[Vec<u8>]) {
    for group in groups {
        let mut hash = Sha256::new();
        hash.update(b"want");
        hash.update(topic.as_bytes());
        hash.update(group);
        let tag = group.get(1..13).map(proof_fields).unwrap_or_default();
        tracing::info!(target: "event", "EVENT kind={} t_ms={} t_us={} peer={} id={:x} topic={} bytes={} want=1{}",
            direction, now_us / 1000, now_us, peer, hash.finalize(), topic,
            topic.len() + group.len(), tag);
    }
}

fn trace_wire(rpc: &proto::Rpc, peer: PeerId) {
    let wants = rpc.control.as_ref().map_or(&[][..], |c| c.wantgroup.as_slice());
    if rpc.publish.is_empty() && rpc.partial.is_none() && wants.is_empty() {
        return;
    }
    let now_us = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros();
    for want in wants {
        trace_want("wire_send", now_us, peer, want.topic_id.as_deref().unwrap_or_default(),
            &want.group_ids);
    }
    for message in &rpc.publish {
        let data = message.data.as_deref().unwrap_or_default();
        let mut hash = Sha256::new();
        hash.update(message.topic.as_bytes());
        hash.update(data);
        tracing::info!(target: "event", "EVENT kind=wire_send t_ms={} t_us={} peer={} id={:x} topic={} bytes={}{}",
            now_us / 1000, now_us, peer, hash.finalize(), message.topic, data.len(),
            proof_tag(&message.topic, data));
    }
    if let Some(partial) = &rpc.partial {
        let group_id = partial.group_id.as_deref().unwrap_or_default();
        let mut hash = Sha256::new();
        hash.update(partial.topic_id.as_deref().unwrap_or_default());
        hash.update(group_id);
        hash.update(partial.partial_message.as_deref().unwrap_or_default());
        hash.update(partial.parts_metadata.as_deref().unwrap_or_default());
        let topic = String::from_utf8_lossy(partial.topic_id.as_deref().unwrap_or_default());
        let body = partial.partial_message.as_ref().map_or(0, Vec::len);
        let bytes = body + partial.parts_metadata.as_ref().map_or(0, Vec::len);
        tracing::info!(target: "event", "EVENT kind=wire_send t_ms={} t_us={} peer={} id={:x} topic={} bytes={} body={}{}",
            now_us / 1000, now_us, peer, hash.finalize(), topic, bytes, body,
            group_tag(&topic, group_id));
    }
}

fn trace_received(rpc: &RpcIn, peer: PeerId) {
    let has_want = rpc
        .control_msgs
        .iter()
        .any(|c| matches!(c, crate::types::ControlAction::WantGroup(_)));
    #[cfg(feature = "partial-messages")]
    if rpc.messages.is_empty() && rpc.partial_message.is_none() && !has_want {
        return;
    }
    let now_us = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros();
    if has_want {
        for control in &rpc.control_msgs {
            if let crate::types::ControlAction::WantGroup(want) = control {
                trace_want("wire_recv", now_us, peer, want.topic_hash.as_str(), &want.groups);
            }
        }
    }
    // Invalid data never enters the application and must not look like a
    // successful payload delivery in the trace.
    for message in &rpc.messages {
        let mut hash = Sha256::new();
        hash.update(message.topic.as_str().as_bytes());
        hash.update(&message.data);
        tracing::info!(target: "event", "EVENT kind=wire_recv t_ms={} t_us={} peer={} id={:x} topic={} bytes={}{}",
            now_us / 1000, now_us, peer, hash.finalize(), message.topic, message.data.len(),
            proof_tag(message.topic.as_str(), &message.data));
    }
    #[cfg(feature = "partial-messages")]
    if let Some(partial) = &rpc.partial_message {
        let mut hash = Sha256::new();
        hash.update(partial.topic_hash.as_str().as_bytes());
        hash.update(&partial.group_id);
        hash.update(partial.body.as_deref().unwrap_or_default());
        hash.update(partial.metadata.as_deref().unwrap_or_default());
        let body = partial.body.as_ref().map_or(0, Vec::len);
        let bytes = body + partial.metadata.as_ref().map_or(0, Vec::len);
        tracing::info!(target: "event", "EVENT kind=wire_recv t_ms={} t_us={} peer={} id={:x} topic={} bytes={} body={}{}",
            now_us / 1000, now_us, peer, hash.finalize(), partial.topic_hash, bytes, body,
            group_tag(partial.topic_hash.as_str(), &partial.group_id));
    }
}

#[allow(clippy::large_enum_variant)]
pub enum Handler {
    Enabled(EnabledHandler),
    Disabled(DisabledHandler),
}

/// Protocol Handler that manages a single long-lived substream with a peer.
pub struct EnabledHandler {
    /// Remote `PeerId` for this `ConnectionHandler`.
    peer_id: PeerId,

    /// Upgrade configuration for the gossipsub protocol.
    listen_protocol: ProtocolConfig,

    /// The single long-lived outbound substream.
    outbound_substream: Option<OutboundSubstreamState>,

    /// The single long-lived inbound substream.
    inbound_substream: Option<InboundSubstreamState>,

    /// Queue of dispatched Rpc messages to send.
    message_queue: Queue,

    /// Flag indicating that an outbound substream is being established to prevent duplicate
    /// requests.
    outbound_substream_establishing: bool,

    /// The number of outbound substreams we have requested.
    outbound_substream_attempts: usize,

    /// The number of inbound substreams that have been created by the peer.
    inbound_substream_attempts: usize,

    /// The type of peer this handler is associated to.
    peer_kind: Option<PeerKind>,

    /// Keeps track on whether we have sent the peer kind to the behaviour.
    // NOTE: Use this flag rather than checking the substream count each poll.
    peer_kind_sent: bool,

    last_io_activity: Instant,

    /// Keeps track of whether this connection is for a peer in the mesh. This is used to make
    /// decisions about the keep alive state for this connection.
    in_mesh: bool,
}

pub enum DisabledHandler {
    /// If the peer doesn't support the gossipsub protocol we do not immediately disconnect.
    /// Rather, we disable the handler and prevent any incoming or outgoing substreams from being
    /// established.
    ProtocolUnsupported {
        /// Keeps track on whether we have sent the peer kind to the behaviour.
        peer_kind_sent: bool,
    },
    /// The maximum number of inbound or outbound substream attempts have happened and thereby the
    /// handler has been disabled.
    MaxSubstreamAttempts,
}

/// State of the inbound substream, opened either by us or by the remote.
enum InboundSubstreamState {
    /// Waiting for a message from the remote. The idle state for an inbound substream.
    WaitingInput(Framed<Stream, GossipsubCodec>),
    /// The substream is being closed.
    Closing(Framed<Stream, GossipsubCodec>),
    /// An error occurred during processing.
    Poisoned,
}

/// State of the outbound substream, opened either by us or by the remote.
enum OutboundSubstreamState {
    /// Waiting for the user to send a message. The idle state for an outbound substream.
    WaitingOutput(Framed<Stream, GossipsubCodec>),
    /// Waiting to send a message to the remote.
    PendingSend(Framed<Stream, GossipsubCodec>, Box<proto::Rpc>),
    /// Waiting to flush the substream so that the data arrives to the remote.
    PendingFlush(Framed<Stream, GossipsubCodec>, Box<proto::Rpc>),
    /// An error occurred during processing.
    Poisoned,
}

impl Handler {
    /// Builds a new [`Handler`].
    pub(crate) fn new(
        peer_id: PeerId,
        protocol_config: ProtocolConfig,
        message_queue: Queue,
    ) -> Self {
        Handler::Enabled(EnabledHandler {
            peer_id,
            listen_protocol: protocol_config,
            inbound_substream: None,
            outbound_substream: None,
            outbound_substream_establishing: false,
            outbound_substream_attempts: 0,
            inbound_substream_attempts: 0,
            message_queue,
            peer_kind: None,
            peer_kind_sent: false,
            last_io_activity: Instant::now(),
            in_mesh: false,
        })
    }
}

impl EnabledHandler {
    fn on_fully_negotiated_inbound(
        &mut self,
        (substream, peer_kind): (Framed<Stream, GossipsubCodec>, PeerKind),
    ) {
        // update the known kind of peer
        if self.peer_kind.is_none() {
            self.peer_kind = Some(peer_kind);
        }

        // new inbound substream. Replace the current one, if it exists.
        tracing::trace!("New inbound substream request");
        self.inbound_substream = Some(InboundSubstreamState::WaitingInput(substream));
    }

    fn on_fully_negotiated_outbound(
        &mut self,
        FullyNegotiatedOutbound { protocol, .. }: FullyNegotiatedOutbound<
            <Handler as ConnectionHandler>::OutboundProtocol,
        >,
    ) {
        let (substream, peer_kind) = protocol;

        // update the known kind of peer
        if self.peer_kind.is_none() {
            self.peer_kind = Some(peer_kind);
        }

        assert!(
            self.outbound_substream.is_none(),
            "Established an outbound substream with one already available"
        );
        self.outbound_substream = Some(OutboundSubstreamState::WaitingOutput(substream));
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<
        ConnectionHandlerEvent<
            <Handler as ConnectionHandler>::OutboundProtocol,
            (),
            <Handler as ConnectionHandler>::ToBehaviour,
        >,
    > {
        if !self.peer_kind_sent
            && let Some(peer_kind) = self.peer_kind.as_ref()
        {
            self.peer_kind_sent = true;
            return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(
                HandlerEvent::PeerKind(*peer_kind),
            ));
        }

        // determine if we need to create the outbound stream
        if !self.message_queue.is_empty()
            && self.outbound_substream.is_none()
            && !self.outbound_substream_establishing
        {
            self.outbound_substream_establishing = true;
            return Poll::Ready(ConnectionHandlerEvent::OutboundSubstreamRequest {
                protocol: SubstreamProtocol::new(self.listen_protocol.clone(), ()),
            });
        }

        // process outbound stream
        loop {
            match self
                .outbound_substream
                .replace(OutboundSubstreamState::Poisoned)
            {
                // outbound idle state
                Some(OutboundSubstreamState::WaitingOutput(substream)) => {
                    if let Poll::Ready(mut message) = Pin::new(&mut self.message_queue).poll_pop(cx)
                    {
                        tracing::debug!(peer=%self.peer_id, ?message, "Sending gossipsub message");
                        if let RpcOut::Publish {
                            ref mut timeout, ..
                        } = message
                            && Pin::new(timeout).poll(cx).is_ready()
                        {
                            // Inform the behaviour and end the poll.
                            self.outbound_substream =
                                Some(OutboundSubstreamState::WaitingOutput(substream));
                            return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(
                                HandlerEvent::MessageDropped(message),
                            ));
                        }
                        self.outbound_substream = Some(OutboundSubstreamState::PendingSend(
                            substream,
                            Box::new(message.into_protobuf()),
                        ));
                        continue;
                    }

                    self.outbound_substream =
                        Some(OutboundSubstreamState::WaitingOutput(substream));
                    break;
                }
                Some(OutboundSubstreamState::PendingSend(mut substream, message)) => {
                    match Sink::poll_ready(Pin::new(&mut substream), cx) {
                        Poll::Ready(Ok(())) => {
                            match Sink::start_send(Pin::new(&mut substream), *message.clone()) {
                                Ok(()) => {
                                    self.outbound_substream =
                                        Some(OutboundSubstreamState::PendingFlush(substream, message))
                                }
                                Err(e) => {
                                    tracing::debug!(
                                        "Failed to send message on outbound stream: {e}"
                                    );
                                    self.outbound_substream = None;
                                    break;
                                }
                            }
                        }
                        Poll::Ready(Err(e)) => {
                            tracing::debug!("Failed to send message on outbound stream: {e}");
                            self.outbound_substream = None;
                            break;
                        }
                        Poll::Pending => {
                            self.outbound_substream =
                                Some(OutboundSubstreamState::PendingSend(substream, message));
                            break;
                        }
                    }
                }
                Some(OutboundSubstreamState::PendingFlush(mut substream, message)) => {
                    match Sink::poll_flush(Pin::new(&mut substream), cx) {
                        Poll::Ready(Ok(())) => {
                            trace_wire(&message, self.peer_id);
                            self.last_io_activity = Instant::now();
                            self.outbound_substream =
                                Some(OutboundSubstreamState::WaitingOutput(substream))
                        }
                        Poll::Ready(Err(e)) => {
                            tracing::debug!("Failed to flush outbound stream: {e}");
                            self.outbound_substream = None;
                            break;
                        }
                        Poll::Pending => {
                            self.outbound_substream =
                                Some(OutboundSubstreamState::PendingFlush(substream, message));
                            break;
                        }
                    }
                }
                None => {
                    self.outbound_substream = None;
                    break;
                }
                Some(OutboundSubstreamState::Poisoned) => {
                    unreachable!("Error occurred during outbound stream processing")
                }
            }
        }

        // Handle inbound messages.
        loop {
            match self
                .inbound_substream
                .replace(InboundSubstreamState::Poisoned)
            {
                // inbound idle state
                Some(InboundSubstreamState::WaitingInput(mut substream)) => {
                    match substream.poll_next_unpin(cx) {
                        Poll::Ready(Some(Ok(message))) => {
                            if let HandlerEvent::Message { rpc, .. } = &message {
                                trace_received(rpc, self.peer_id);
                            }
                            self.last_io_activity = Instant::now();
                            self.inbound_substream =
                                Some(InboundSubstreamState::WaitingInput(substream));
                            return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(message));
                        }
                        Poll::Ready(Some(Err(error))) => {
                            tracing::debug!("Failed to read from inbound stream: {error}");
                            // Close this side of the stream. If the
                            // peer is still around, they will re-establish their
                            // outbound stream i.e. our inbound stream.
                            self.inbound_substream =
                                Some(InboundSubstreamState::Closing(substream));
                        }
                        // peer closed the stream
                        Poll::Ready(None) => {
                            tracing::debug!("Inbound stream closed by remote");
                            self.inbound_substream =
                                Some(InboundSubstreamState::Closing(substream));
                        }
                        Poll::Pending => {
                            self.inbound_substream =
                                Some(InboundSubstreamState::WaitingInput(substream));
                            break;
                        }
                    }
                }
                Some(InboundSubstreamState::Closing(mut substream)) => {
                    match Sink::poll_close(Pin::new(&mut substream), cx) {
                        Poll::Ready(res) => {
                            if let Err(e) = res {
                                // Don't close the connection but just drop the inbound substream.
                                // In case the remote has more to send, they will open up a new
                                // substream.
                                tracing::debug!("Inbound substream error while closing: {e}");
                            }
                            self.inbound_substream = None;
                            break;
                        }
                        Poll::Pending => {
                            self.inbound_substream =
                                Some(InboundSubstreamState::Closing(substream));
                            break;
                        }
                    }
                }
                None => {
                    self.inbound_substream = None;
                    break;
                }
                Some(InboundSubstreamState::Poisoned) => {
                    unreachable!("Error occurred during inbound stream processing")
                }
            }
        }

        Poll::Pending
    }
}

impl ConnectionHandler for Handler {
    type FromBehaviour = HandlerIn;
    type ToBehaviour = HandlerEvent;
    type InboundOpenInfo = ();
    type InboundProtocol = either::Either<ProtocolConfig, DeniedUpgrade>;
    type OutboundOpenInfo = ();
    type OutboundProtocol = ProtocolConfig;

    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol> {
        match self {
            Handler::Enabled(handler) => {
                SubstreamProtocol::new(either::Either::Left(handler.listen_protocol.clone()), ())
            }
            Handler::Disabled(_) => {
                SubstreamProtocol::new(either::Either::Right(DeniedUpgrade), ())
            }
        }
    }

    fn on_behaviour_event(&mut self, message: HandlerIn) {
        match self {
            Handler::Enabled(handler) => match message {
                HandlerIn::JoinedMesh => {
                    handler.in_mesh = true;
                }
                HandlerIn::LeftMesh => {
                    handler.in_mesh = false;
                }
            },
            Handler::Disabled(_) => {
                tracing::debug!(?message, "Handler is disabled. Dropping message");
            }
        }
    }

    fn connection_keep_alive(&self) -> bool {
        matches!(self, Handler::Enabled(h) if h.in_mesh)
    }

    #[tracing::instrument(level = "trace", name = "ConnectionHandler::poll", skip(self, cx))]
    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ConnectionHandlerEvent<Self::OutboundProtocol, (), Self::ToBehaviour>> {
        match self {
            Handler::Enabled(handler) => handler.poll(cx),
            Handler::Disabled(DisabledHandler::ProtocolUnsupported { peer_kind_sent }) => {
                if !*peer_kind_sent {
                    *peer_kind_sent = true;
                    return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(
                        HandlerEvent::PeerKind(PeerKind::NotSupported),
                    ));
                }

                Poll::Pending
            }
            Handler::Disabled(DisabledHandler::MaxSubstreamAttempts) => Poll::Pending,
        }
    }

    fn on_connection_event(
        &mut self,
        event: ConnectionEvent<Self::InboundProtocol, Self::OutboundProtocol>,
    ) {
        match self {
            Handler::Enabled(handler) => {
                if event.is_inbound() {
                    handler.inbound_substream_attempts += 1;

                    if handler.inbound_substream_attempts == MAX_SUBSTREAM_ATTEMPTS {
                        tracing::warn!(
                            "The maximum number of inbound substreams attempts has been exceeded"
                        );
                        *self = Handler::Disabled(DisabledHandler::MaxSubstreamAttempts);
                        return;
                    }
                }

                if event.is_outbound() {
                    handler.outbound_substream_establishing = false;

                    handler.outbound_substream_attempts += 1;

                    if handler.outbound_substream_attempts == MAX_SUBSTREAM_ATTEMPTS {
                        tracing::warn!(
                            "The maximum number of outbound substream attempts has been exceeded"
                        );
                        *self = Handler::Disabled(DisabledHandler::MaxSubstreamAttempts);
                        return;
                    }
                }

                match event {
                    ConnectionEvent::FullyNegotiatedInbound(FullyNegotiatedInbound {
                        protocol,
                        ..
                    }) => match protocol {
                        Either::Left(protocol) => handler.on_fully_negotiated_inbound(protocol),
                        Either::Right(v) => libp2p_core::util::unreachable(v),
                    },
                    ConnectionEvent::FullyNegotiatedOutbound(fully_negotiated_outbound) => {
                        handler.on_fully_negotiated_outbound(fully_negotiated_outbound)
                    }
                    ConnectionEvent::DialUpgradeError(DialUpgradeError {
                        error: StreamUpgradeError::Timeout,
                        ..
                    }) => {
                        tracing::debug!("Dial upgrade error: Protocol negotiation timeout");
                    }
                    ConnectionEvent::DialUpgradeError(DialUpgradeError {
                        error: StreamUpgradeError::Apply(e),
                        ..
                    }) => libp2p_core::util::unreachable(e),
                    ConnectionEvent::DialUpgradeError(DialUpgradeError {
                        error: StreamUpgradeError::NegotiationFailed,
                        ..
                    }) => {
                        // The protocol is not supported
                        tracing::debug!(
                            "The remote peer does not support gossipsub on this connection"
                        );
                        *self = Handler::Disabled(DisabledHandler::ProtocolUnsupported {
                            peer_kind_sent: false,
                        });
                    }
                    ConnectionEvent::DialUpgradeError(DialUpgradeError {
                        error: StreamUpgradeError::Io(e),
                        ..
                    }) => {
                        tracing::debug!("Protocol negotiation failed: {e}")
                    }
                    _ => {}
                }
            }
            Handler::Disabled(_) => {}
        }
    }
}
