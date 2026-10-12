//! proof-broadcast: pull-gated topics (`gate_topic` / `want_group`).

use libp2p_identity::PeerId;
use libp2p_swarm::{ConnectionId, NetworkBehaviour};

use super::{DefaultBehaviourTestBuilder, disconnect_peer};
use crate::{
    Behaviour,
    config::Config,
    handler::HandlerEvent,
    queue::Queue,
    topic::TopicHash,
    traffic::ControlKind,
    types::{ControlAction, PeerKind, RawMessage, RpcIn, RpcOut, WantGroup},
};

/// Group = first byte; 0 leaves a message ungated.
fn first_byte(data: &[u8]) -> Option<Vec<u8>> {
    data.first().filter(|&&b| b != 0).map(|&b| vec![b])
}

fn network(peers: usize) -> (Behaviour, Vec<PeerId>, std::collections::HashMap<PeerId, Queue>, TopicHash) {
    let (mut gs, peers, queues, topics) = DefaultBehaviourTestBuilder::default()
        .peer_no(peers)
        .topics(vec![String::from("pull")])
        .to_subscribe(true)
        .gs_config(Config::default())
        .peer_kind(PeerKind::Gossipsubv1_2)
        .create_network();
    gs.gate_topic(topics[0].clone(), first_byte);
    (gs, peers, queues, topics[0].clone())
}

/// Drain every queue; per peer, the data of the messages published to it.
fn published(queues: &mut std::collections::HashMap<PeerId, Queue>, peer: &PeerId) -> Vec<Vec<u8>> {
    let queue = queues.get_mut(peer).unwrap();
    let mut out = Vec::new();
    while !queue.is_empty() {
        if let Some(RpcOut::Publish { message, .. }) = queue.try_pop() {
            out.push(message.data);
        }
    }
    out
}

fn drain(queues: &mut std::collections::HashMap<PeerId, Queue>) {
    for queue in queues.values_mut() {
        while queue.try_pop().is_some() {}
    }
}

fn want(gs: &mut Behaviour, from: PeerId, topic: &TopicHash, group: u8) {
    gs.on_connection_handler_event(
        from,
        ConnectionId::new_unchecked(0),
        HandlerEvent::Message {
            rpc: RpcIn {
                messages: vec![],
                subscriptions: vec![],
                #[cfg(feature = "partial-messages")]
                partial_message: None,
                control_msgs: vec![ControlAction::WantGroup(WantGroup {
                    topic_hash: topic.clone(),
                    groups: vec![vec![group]],
                })],
            },
            invalid_messages: vec![],
        },
    );
}

#[test]
fn publish_waits_for_want_then_replays() {
    let (mut gs, peers, mut queues, topic) = network(3);
    drain(&mut queues);
    // Nobody asked yet: published, but sent to no one.
    gs.publish(topic.clone(), vec![7, 1]).expect("gated publish succeeds");
    for peer in &peers {
        assert!(published(&mut queues, peer).is_empty());
    }
    // peers[1] asks: it gets what we hold, and later messages of the group.
    want(&mut gs, peers[1], &topic, 7);
    assert_eq!(published(&mut queues, &peers[1]), vec![vec![7, 1]]);
    gs.publish(topic.clone(), vec![7, 2]).unwrap();
    gs.publish(topic.clone(), vec![9, 1]).unwrap();
    assert_eq!(published(&mut queues, &peers[1]), vec![vec![7, 2]]);
    assert!(published(&mut queues, &peers[0]).is_empty());
    assert!(published(&mut queues, &peers[2]).is_empty());
    // Ungated messages use the mesh as usual.
    gs.publish(topic.clone(), vec![0, 1]).unwrap();
    let reached = peers
        .iter()
        .filter(|p| !published(&mut queues, p).is_empty())
        .count();
    assert!(reached > 0);
}

#[test]
fn forwards_only_to_wanters_and_never_back() {
    let (mut gs, peers, mut queues, topic) = network(3);
    drain(&mut queues);
    want(&mut gs, peers[1], &topic, 7);
    let message = RawMessage {
        source: Some(PeerId::random()),
        data: vec![7, 42],
        sequence_number: Some(1),
        topic: topic.clone(),
        signature: None,
        key: None,
        validated: true,
    };
    // Default config forwards without waiting for validation.
    gs.handle_received_message(message, &peers[0]);
    assert_eq!(published(&mut queues, &peers[1]), vec![vec![7, 42]]);
    assert!(published(&mut queues, &peers[0]).is_empty());
    assert!(published(&mut queues, &peers[2]).is_empty());
    // A late ask is served from what we hold; the sender is never served back.
    want(&mut gs, peers[2], &topic, 7);
    want(&mut gs, peers[0], &topic, 7);
    assert_eq!(published(&mut queues, &peers[2]), vec![vec![7, 42]]);
    assert!(published(&mut queues, &peers[0]).is_empty());
}

#[test]
fn want_group_is_a_counted_control_message() {
    let (mut gs, peers, mut queues, topic) = network(2);
    drain(&mut queues);
    assert!(gs.want_group(topic.clone(), vec![vec![7]], peers[0]));
    assert!(!gs.want_group(topic.clone(), vec![], peers[0]));
    let queue = queues.get_mut(&peers[0]).unwrap();
    let rpc = std::iter::from_fn(|| queue.try_pop())
        .find(|rpc| matches!(rpc, RpcOut::WantGroup(_)))
        .expect("WANT queued");
    let proto = rpc.into_protobuf();
    let want = &proto.control.expect("control").wantgroup[0];
    assert_eq!(want.topic_id.as_deref(), Some(topic.as_str()));
    assert_eq!(want.group_ids, vec![vec![7]]);
    let tx = &gs.traffic().per_topic[&topic].tx;
    assert!(tx.control_bytes[ControlKind::WantGroup.index()] > 0);
}

#[test]
fn disconnect_forgets_wants() {
    let (mut gs, peers, mut queues, topic) = network(2);
    drain(&mut queues);
    want(&mut gs, peers[1], &topic, 7);
    assert_eq!(gs.gated[&topic].wanters(&[7]), vec![peers[1]]);
    disconnect_peer(&mut gs, &peers[1]);
    assert!(gs.gated[&topic].wanters(&[7]).is_empty());
}
