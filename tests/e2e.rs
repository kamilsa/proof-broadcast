//! In-process end-to-end runs: real swarms over localhost QUIC.
//!
//! `subnets` × 2 L1 provers + 4 L2 provers. L1s dial every L2; L2s dial each
//! other. Every L2 must collect one proof per subnet and finish aggregating.

use std::sync::atomic::{AtomicU16, Ordering};

use clap::Parser;
use futures::future::join_all;
use proof_broadcast::{Cli, Mode, NodeReport, run};

const PROVERS_PER_SUBNET: usize = 2;
const L2_COUNT: usize = 4;
const AGGREGATION_MS: u64 = 200;

static NEXT_PORT: AtomicU16 = AtomicU16::new(0);

fn base_port() -> u16 {
    // Give each network its own port block; offset by pid for parallel runs.
    let block = NEXT_PORT.fetch_add(1, Ordering::SeqCst);
    30_000 + (std::process::id() % 400) as u16 * 60 + block * 15
}

fn addr(port: u16) -> String {
    format!("/ip4/127.0.0.1/udp/{port}/quic-v1")
}

async fn run_network(mode: Mode, subnets: usize, extra: &[&str]) -> (Vec<NodeReport>, Vec<NodeReport>) {
    let base = base_port();
    let l1_count = subnets * PROVERS_PER_SUBNET;
    let l2_port = |i: usize| base + (l1_count + i) as u16;
    let common = |seed: u64, port: u16| {
        let mut args = vec![
            "proof-broadcast".to_string(),
            format!("--mode={}", mode),
            format!("--seed={seed}"),
            "--listen-ip=127.0.0.1".to_string(),
            format!("--listen-port={port}"),
            format!("--subnets={subnets}"),
            "--proof-size-kib=64".to_string(),
            "--chunk-count=16".to_string(),
            format!("--aggregation-ms={AGGREGATION_MS}"),
            "--warmup-secs=4".to_string(),
            "--observe-secs=10".to_string(),
            "--proofs-mesh-n=3".to_string(),
            "--proofs-mesh-n-low=2".to_string(),
            "--proofs-mesh-n-high=4".to_string(),
            "--proofs-mesh-outbound-min=1".to_string(),
        ];
        args.extend(extra.iter().map(|a| a.to_string()));
        args
    };

    let mut clis = Vec::new();
    for i in 0..l1_count {
        let mut args = common(100 + i as u64, base + i as u16);
        args.push("--role=l1".into());
        args.push(format!("--subnet={}", i / PROVERS_PER_SUBNET));
        args.push(format!("--prover={}", i % PROVERS_PER_SUBNET));
        args.push(format!("--publish-delay-ms={}", i * 150));
        for j in 0..L2_COUNT {
            args.push(format!("--peer={}", addr(l2_port(j))));
        }
        clis.push(Cli::parse_from(args));
    }
    for i in 0..L2_COUNT {
        let mut args = common(200 + i as u64, l2_port(i));
        args.push("--role=l2".into());
        args.push(format!("--prover={i}"));
        for j in (i + 1)..L2_COUNT {
            args.push(format!("--peer={}", addr(l2_port(j))));
        }
        clis.push(Cli::parse_from(args));
    }
    for cli in &clis {
        cli.validate().expect("valid test config");
    }

    let handles: Vec<_> = clis.into_iter().map(|cli| tokio::spawn(run(cli))).collect();
    let mut reports: Vec<NodeReport> = join_all(handles)
        .await
        .into_iter()
        .map(|r| r.expect("node task"))
        .collect();
    let l2 = reports.split_off(l1_count);
    (reports, l2)
}

fn check(label: &str, subnets: usize, l1: &[NodeReport], l2: &[NodeReport]) {
    assert!(l1.iter().all(|r| r.published), "{label}: every L1 publishes");
    for (i, r) in l2.iter().enumerate() {
        eprintln!(
            "{label} L2 {i}: rx={} tx={} redundant={} dup_chunks={} declined={} all={:?} agg={:?} \
             merges={} discarded={} published={} fetched={} agg_declined={} dropped={}",
            r.rx_bytes, r.tx_bytes, r.redundant_proofs, r.duplicate_chunks, r.declined,
            r.all_subnets_ms, r.aggregate_ms, r.merges_run, r.merges_discarded,
            r.intermediates_published, r.intermediates_fetched, r.intermediates_declined,
            r.items_dropped
        );
        assert_eq!(r.subnets_done, subnets, "{label}: L2 {i} covered every subnet: {r:?}");
        assert!(r.committed.iter().all(Option::is_some), "{label}: L2 {i} chose every subnet");
        let aggregated = r.aggregate_ms.expect("aggregate completes");
        assert!(aggregated >= r.all_subnets_ms.expect("all subnets"));
        // Every kept merge joins two disjoint items into one.
        assert!(
            r.merges_run - r.merges_discarded < subnets,
            "{label}: L2 {i} ran too many merges: {r:?}"
        );
        assert!(r.rx_bytes > 0);
    }
}

fn check_plain(mode: Mode, l2: &[NodeReport]) {
    for (i, r) in l2.iter().enumerate() {
        let first = r.first_proof_ms.expect("first proof");
        let aggregated = r.aggregate_ms.expect("aggregate completes");
        assert!(
            aggregated >= first + (r.committed.len() as u64 - 1) * AGGREGATION_MS,
            "{mode}: L2 {i} aggregation takes (subnets-1) recursions: {r:?}"
        );
        assert_eq!(r.merges_run, r.committed.len() - 1);
        assert_eq!(r.intermediates_published + r.intermediates_fetched, 0);
    }
}

fn check_intermediates(label: &str, l2: &[NodeReport]) {
    let published: usize = l2.iter().map(|r| r.intermediates_published).sum();
    assert!(published > 0, "{label}: some L2 published an intermediate aggregate");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gossipsub_mode_delivers_one_proof_per_subnet() {
    let (l1, l2) = run_network(Mode::Gossipsub, 2, &[]).await;
    check("gossipsub", 2, &l1, &l2);
    check_plain(Mode::Gossipsub, &l2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn partial_mode_delivers_one_proof_per_subnet() {
    let (l1, l2) = run_network(Mode::Partial, 2, &[]).await;
    check("partial", 2, &l1, &l2);
    check_plain(Mode::Partial, &l2);
    // L1s never subscribe, so they never receive anyone's proof.
    for r in &l1 {
        assert_eq!(r.subnets_done, 0);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gossipsub_mode_with_intermediate_proofs() {
    let (l1, l2) = run_network(Mode::Gossipsub, 4, &["--intermediate-proofs"]).await;
    check("gossipsub+intermediate", 4, &l1, &l2);
    check_intermediates("gossipsub+intermediate", &l2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn partial_mode_with_intermediate_proofs() {
    let (l1, l2) = run_network(Mode::Partial, 4, &["--intermediate-proofs"]).await;
    check("partial+intermediate", 4, &l1, &l2);
    check_intermediates("partial+intermediate", &l2);
}

/// 4 subnets × 1 L1 (subnet `s` published `delays[s]` ms after the epoch at
/// 4 s), 4 L2s, and one late L2 that starts `late_ms` after the others and
/// so never sees the proofs published before it joined. Every L2 publishes
/// its intermediate aggregates; merges take 2.5 s.
async fn run_late_joiner(
    mode: Mode,
    delays: [u64; 4],
    late_ms: u64,
    extra: &[&str],
) -> (NodeReport, Vec<NodeReport>) {
    const SUBNETS: usize = 4;
    const AGG_MS: u64 = 2500;
    const OBSERVE: u64 = 14;
    let base = base_port();
    let l2_port = |i: usize| base + (SUBNETS + i) as u16;
    let late_port = l2_port(L2_COUNT);
    let common = |seed: u64, port: u16, warmup: u64, observe: u64| {
        vec![
            "proof-broadcast".to_string(),
            format!("--mode={mode}"),
            format!("--seed={seed}"),
            "--listen-ip=127.0.0.1".to_string(),
            format!("--listen-port={port}"),
            format!("--subnets={SUBNETS}"),
            "--proof-size-kib=64".to_string(),
            "--chunk-count=16".to_string(),
            format!("--aggregation-ms={AGG_MS}"),
            format!("--warmup-secs={warmup}"),
            format!("--observe-secs={observe}"),
            "--proofs-mesh-n=3".to_string(),
            "--proofs-mesh-n-low=2".to_string(),
            "--proofs-mesh-n-high=5".to_string(),
            "--proofs-mesh-outbound-min=1".to_string(),
            "--intermediate-proofs".to_string(),
        ]
        .into_iter()
        .chain(extra.iter().map(|a| a.to_string()))
        .collect::<Vec<_>>()
    };
    let mut clis = Vec::new();
    for (s, delay) in delays.iter().enumerate() {
        let mut args = common(300 + s as u64, base + s as u16, 4, OBSERVE);
        args.push("--role=l1".into());
        args.push(format!("--subnet={s}"));
        args.push(format!("--publish-delay-ms={delay}"));
        for j in 0..L2_COUNT {
            args.push(format!("--peer={}", addr(l2_port(j))));
        }
        clis.push(Cli::parse_from(args));
    }
    for i in 0..L2_COUNT {
        let mut args = common(400 + i as u64, l2_port(i), 4, OBSERVE);
        args.push("--role=l2".into());
        args.push(format!("--prover={i}"));
        for j in (i + 1)..L2_COUNT {
            args.push(format!("--peer={}", addr(l2_port(j))));
        }
        clis.push(Cli::parse_from(args));
    }
    let mut late = common(499, late_port, 0, OBSERVE);
    late.push("--role=l2".into());
    late.push(format!("--prover={L2_COUNT}"));
    for j in 0..L2_COUNT {
        late.push(format!("--peer={}", addr(l2_port(j))));
    }
    let late = Cli::parse_from(late);
    late.validate().expect("valid late config");

    let handles: Vec<_> = clis.into_iter().map(|cli| tokio::spawn(run(cli))).collect();
    tokio::time::sleep(std::time::Duration::from_millis(late_ms)).await;
    let late = tokio::spawn(run(late));
    let mut reports: Vec<NodeReport> = join_all(handles)
        .await
        .into_iter()
        .map(|r| r.expect("node task"))
        .collect();
    let late = late.await.expect("late node task");
    let l2 = reports.split_off(SUBNETS);
    (late, l2)
}

fn check_late_joiner(label: &str, late: &NodeReport, l2: &[NodeReport]) {
    eprintln!(
        "{label} late L2: fetched={} merges={} discarded={} dropped={} published={} agg={:?}",
        late.intermediates_fetched, late.merges_run, late.merges_discarded, late.items_dropped,
        late.intermediates_published, late.aggregate_ms
    );
    assert!(l2.iter().all(|r| r.aggregate_ms.is_some()), "{label}: every L2 aggregates");
    assert!(l2.iter().all(|r| r.intermediates_published > 0), "{label}: L2s publish {{0,1}}");
    assert_eq!(late.subnets_done, 4, "{label}: late L2 covers every subnet");
    assert!(late.committed.iter().all(Option::is_some));
    assert!(late.aggregate_ms.is_some(), "{label}: late L2 aggregates");
    assert_eq!(late.intermediates_fetched, 1, "{label}: late L2 fetched the {{0,1}} aggregate");
    // {2,3}, then the final merge: the {0,1} recursion was saved.
    assert_eq!(late.merges_run, 2, "{label}: one merge saved");
}

/// Subnets 0, 1 at 4 s, the late L2 at 4.3 s, {0,1} aggregates at ~6.5 s,
/// subnets 2, 3 at 7.5 s: the late L2 never sees subnets 0 and 1 alone.
const MISSED_BOTH: [u64; 4] = [0, 0, 3500, 3500];

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gossipsub_late_l2_fetches_intermediate_aggregate() {
    let (late, l2) = run_late_joiner(Mode::Gossipsub, MISSED_BOTH, 4300, &[]).await;
    check_late_joiner("gossipsub", &late, &l2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn partial_late_l2_fetches_intermediate_aggregate() {
    let (late, l2) = run_late_joiner(Mode::Partial, MISSED_BOTH, 4300, &[]).await;
    check_late_joiner("partial", &late, &l2);
}

/// Subnet 0 at 4 s, the late L2 at 4.3 s, subnet 1 at 6 s (the late L2 holds
/// {1}), {0,1} aggregates at ~8.5 s, subnets 2, 3 at 10 s. Under `subsume`
/// the late L2 takes {0,1} and drops its own {1}.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gossipsub_late_l2_subsumes_held_proof() {
    let (late, l2) = run_late_joiner(
        Mode::Gossipsub,
        [0, 2000, 6000, 6000],
        4300,
        &["--intermediate-fetch=subsume"],
    )
    .await;
    check_late_joiner("gossipsub+subsume", &late, &l2);
    assert_eq!(late.items_dropped, 1, "the held {{1}} was replaced by {{0,1}}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn partial_mode_with_subsuming_intermediate_proofs() {
    let (l1, l2) = run_network(
        Mode::Partial,
        4,
        &["--intermediate-proofs", "--intermediate-fetch=subsume"],
    )
    .await;
    check("partial+subsume", 4, &l1, &l2);
    check_intermediates("partial+subsume", &l2);
}
