//! L2 aggregation: 2→1 recursive proof composition, pipelined with arrival.
//!
//! Every held proof (a subnet proof, or an intermediate aggregate fetched
//! from another L2) enters a pool. Whenever a prover worker is idle and the
//! pool holds two items, the pair is merged by one leanVM 2→1 recursion,
//! which takes `aggregation_ms` (leanVM README: 0.287 s on an M4 Max). The
//! merged item re-enters the pool; the job is done once one item covers
//! every subnet. The scheduler is pure; the node loop turns each [`Job`] into
//! a timer, which under Shadow advances simulated time only.
//!
//! Subsume support: when an L2 starts fetching an aggregate that fully
//! contains some of its items, it [`reserve`](Aggregator::reserve)s the
//! aggregate's committees. Items inside the reservation are frozen (kept,
//! but not merged) until the aggregate arrives; then they are dropped, and
//! running merges inside it are discarded when they finish.

use crate::proof::{Committees, mask_of};

/// Subnets covered by one pooled item: a leaf proof covers one subnet, an
/// aggregate covers the union of its two inputs. Kept sorted.
pub type Subnets = Vec<u16>;

/// One 2→1 recursion merging two disjoint items.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Job {
    pub left: Subnets,
    pub right: Subnets,
}

impl Job {
    pub fn covered(&self) -> usize {
        self.left.len() + self.right.len()
    }

    /// The aggregate this job produces.
    pub fn merged(&self) -> Subnets {
        let mut out: Subnets = self.left.iter().chain(&self.right).copied().collect();
        out.sort_unstable();
        out
    }
}

/// Render subnets as `0-3-5` for event lines: no spaces, never parseable as
/// a float by the analyzers (`0.3` would be), and `none` when empty.
pub fn subnet_list(subnets: &[u16]) -> String {
    if subnets.is_empty() {
        return "none".to_string();
    }
    subnets.iter().map(u16::to_string).collect::<Vec<_>>().join("-")
}

/// What one scheduler step did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Step {
    /// Merges to start now.
    pub jobs: Vec<Job>,
    /// Items dropped because an aggregate containing them arrived.
    pub dropped: Vec<Subnets>,
    /// [`Aggregator::job_done`]: false if the result was discarded.
    pub kept: bool,
}

#[derive(Debug, Clone)]
pub struct Aggregator {
    subnets: usize,
    workers: usize,
    pool: Vec<Subnets>,
    /// Outputs of running merges.
    running: Vec<Subnets>,
    /// Running outputs to discard on completion.
    doomed: Vec<Subnets>,
    /// Committees of aggregates being fetched to replace items.
    reserved: Vec<Committees>,
    /// Held items inside a reservation: kept, never merged.
    frozen: Vec<Subnets>,
    complete: bool,
}

impl Aggregator {
    pub fn new(subnets: usize, workers: usize) -> Self {
        Self {
            subnets,
            workers: workers.max(1),
            pool: Vec::new(),
            running: Vec::new(),
            doomed: Vec::new(),
            reserved: Vec::new(),
            frozen: Vec::new(),
            complete: false,
        }
    }

    /// The proof for `subnet` became available. Returns the jobs to start now.
    pub fn add_leaf(&mut self, subnet: u16) -> Vec<Job> {
        self.add_item(vec![subnet]).jobs
    }

    /// A proof covering `item` became available: a subnet proof, a fetched
    /// aggregate, or (via [`job_done`](Self::job_done)) a finished merge.
    /// Completes a reservation when `item` is exactly a reserved aggregate.
    pub fn add_item(&mut self, mut item: Subnets) -> Step {
        item.sort_unstable();
        let mask = mask_of(&item);
        let mut step = Step {
            kept: true,
            ..Step::default()
        };
        if let Some(pos) = self.reserved.iter().position(|&r| r == mask) {
            self.reserved.swap_remove(pos);
            let (dropped, frozen) = std::mem::take(&mut self.frozen)
                .into_iter()
                .partition(|f| inside(f, mask));
            self.frozen = frozen;
            step.dropped = dropped;
            let doomed: Vec<Subnets> =
                self.running.iter().filter(|r| inside(r, mask)).cloned().collect();
            self.doomed.extend(doomed);
        } else if self.reserved.iter().any(|&r| mask & !r == 0) {
            self.frozen.push(item);
            // A finished merge may have freed a worker.
            step.jobs = self.schedule();
            return step;
        }
        if item.len() >= self.subnets {
            self.complete = true;
        }
        self.pool.push(item);
        step.jobs = self.schedule();
        step
    }

    /// A merge finished, yielding `item` (its [`Job::merged`] subnets).
    pub fn job_done(&mut self, item: Subnets) -> Step {
        if let Some(pos) = self.running.iter().position(|r| *r == item) {
            self.running.swap_remove(pos);
        }
        if let Some(pos) = self.doomed.iter().position(|d| *d == item) {
            self.doomed.swap_remove(pos);
            return Step {
                jobs: self.schedule(),
                ..Step::default()
            };
        }
        self.add_item(item)
    }

    /// An aggregate covering `mask`, which fully contains some of our items,
    /// is being fetched: freeze those items until it arrives.
    pub fn reserve(&mut self, mask: Committees) {
        self.reserved.push(mask);
        let (frozen, pool) = std::mem::take(&mut self.pool)
            .into_iter()
            .partition(|p| inside(p, mask));
        self.pool = pool;
        self.frozen.extend::<Vec<_>>(frozen);
    }

    /// Start as many merges as idle workers allow, pairing the items covering
    /// the fewest subnets first so the recursion tree stays balanced.
    fn schedule(&mut self) -> Vec<Job> {
        let mut jobs = Vec::new();
        while !self.complete && self.running.len() < self.workers && self.pool.len() >= 2 {
            // Stable: among equally sized items the newest are paired first.
            self.pool.sort_by_key(|item| std::cmp::Reverse(item.len()));
            let left = self.pool.pop().expect("pool has two items");
            let right = self.pool.pop().expect("pool has two items");
            let job = Job { left, right };
            self.running.push(job.merged());
            jobs.push(job);
        }
        jobs
    }

    /// Committees of every live unit (pooled items and the outputs of
    /// running merges that will be kept). Frozen items are inside a pending
    /// download, which the ledger already counts.
    pub fn units(&self) -> Vec<Committees> {
        self.pool
            .iter()
            .chain(self.running.iter().filter(|r| !self.doomed.contains(r)))
            .map(|item| mask_of(item))
            .collect()
    }

    pub fn is_complete(&self) -> bool {
        self.complete
    }

    pub fn running(&self) -> usize {
        self.running.len()
    }
}

fn inside(item: &[u16], mask: Committees) -> bool {
    mask_of(item) & !mask == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Reverse;
    use std::collections::BinaryHeap;

    /// Discrete-event run: leaves arrive at `arrivals` (ms), each job takes
    /// `dur` ms. Returns (completion time, jobs run, peak concurrency).
    fn simulate(subnets: usize, workers: usize, dur: u64, arrivals: &[u64]) -> (u64, usize, usize) {
        let mut agg = Aggregator::new(subnets, workers);
        // (time, kind: 0 = job done, 1 = leaf), item
        let mut events: BinaryHeap<Reverse<(u64, u8, Subnets)>> = arrivals
            .iter()
            .enumerate()
            .map(|(i, &t)| Reverse((t, 1, vec![i as u16])))
            .collect();
        let (mut jobs_run, mut peak) = (0, 0);
        while let Some(Reverse((now, kind, item))) = events.pop() {
            let jobs = if kind == 1 { agg.add_leaf(item[0]) } else { agg.job_done(item).jobs };
            if agg.is_complete() {
                return (now, jobs_run, peak);
            }
            for job in jobs {
                jobs_run += 1;
                events.push(Reverse((now + dur, 0, job.merged())));
            }
            peak = peak.max(agg.running());
        }
        panic!("aggregation never completed");
    }

    #[test]
    fn all_at_once_single_worker_is_sequential() {
        let (done, jobs, peak) = simulate(16, 1, 290, &[0; 16]);
        assert_eq!(jobs, 15);
        assert_eq!(done, 15 * 290);
        assert_eq!(peak, 1);
    }

    #[test]
    fn slow_arrivals_finish_one_job_after_last() {
        let arrivals: Vec<u64> = (0..16).map(|i| i * 1000).collect();
        let (done, jobs, _) = simulate(16, 1, 290, &arrivals);
        assert_eq!(jobs, 15);
        assert_eq!(done, 15_000 + 290);
    }

    #[test]
    fn enough_workers_give_log_depth() {
        let (done, jobs, peak) = simulate(16, 8, 290, &[0; 16]);
        assert_eq!(jobs, 15);
        assert_eq!(done, 4 * 290);
        assert_eq!(peak, 8);
    }

    #[test]
    fn concurrency_never_exceeds_workers() {
        let arrivals: Vec<u64> = (0..16).map(|i| (i * 37) % 200).collect();
        for workers in 1..=4 {
            let (_, jobs, peak) = simulate(16, workers, 290, &arrivals);
            assert_eq!(jobs, 15);
            assert!(peak <= workers);
        }
    }

    #[test]
    fn single_subnet_needs_no_recursion() {
        let mut agg = Aggregator::new(1, 1);
        assert!(agg.add_leaf(0).is_empty());
        assert!(agg.is_complete());
    }

    #[test]
    fn pairs_smallest_items_first() {
        let mut agg = Aggregator::new(8, 1);
        assert_eq!(agg.add_leaf(3), vec![]);
        let first = agg.add_leaf(5);
        assert_eq!(first, vec![Job { left: vec![5], right: vec![3] }]);
        assert_eq!(first[0].merged(), vec![3, 5]);
        assert_eq!(agg.add_leaf(0), vec![]);
        assert_eq!(agg.add_leaf(7), vec![]);
        // Pool now {0, 7}; the finished {3,5} waits behind the two leaves.
        assert_eq!(agg.job_done(vec![3, 5]).jobs, vec![Job { left: vec![7], right: vec![0] }]);
    }

    #[test]
    fn complete_aggregate_covers_every_subnet() {
        let arrivals = [0u64; 16];
        let (_, jobs, _) = simulate(16, 3, 10, &arrivals);
        assert_eq!(jobs, 15);
        assert_eq!(subnet_list(&[0, 3, 12]), "0-3-12");
        assert_eq!(subnet_list(&[]), "none");
    }

    #[test]
    fn fetched_aggregate_saves_merges() {
        let mut agg = Aggregator::new(4, 1);
        assert!(agg.add_item(vec![2, 3]).jobs.is_empty());
        assert_eq!(agg.units(), vec![0b1100]);
        let jobs = agg.add_item(vec![1, 0]).jobs;
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].merged(), vec![0, 1, 2, 3]);
        assert_eq!(agg.units(), vec![0b1111]);
        agg.job_done(jobs[0].merged());
        assert!(agg.is_complete());
    }

    #[test]
    fn reservation_freezes_then_drops_contained_items() {
        let mut agg = Aggregator::new(8, 1);
        agg.add_leaf(0);
        let running = agg.add_leaf(1);
        assert_eq!(running[0].merged(), vec![0, 1]);
        agg.add_leaf(2);
        agg.add_leaf(5);
        // Pool {2}, {5}; running {0,1}. Fetch {0,1,2,3}.
        agg.reserve(0b1111);
        assert_eq!(agg.units(), vec![0b10_0000, 0b11]);
        // A leaf inside the reservation is frozen, not pooled.
        let step = agg.add_item(vec![3]);
        assert!(step.jobs.is_empty() && step.kept);
        // The running merge finishes before the aggregate: frozen too.
        let step = agg.job_done(vec![0, 1]);
        assert!(step.kept && step.jobs.is_empty());
        assert_eq!(agg.units(), vec![0b10_0000]);
        // The aggregate arrives: {2}, {3}, {0,1} dropped; merge with {5}.
        let step = agg.add_item(vec![0, 1, 2, 3]);
        let mut dropped = step.dropped.clone();
        dropped.sort();
        assert_eq!(dropped, vec![vec![0, 1], vec![2], vec![3]]);
        assert_eq!(step.jobs.len(), 1);
        assert_eq!(step.jobs[0].merged(), vec![0, 1, 2, 3, 5]);
    }

    #[test]
    fn merge_running_at_release_is_discarded() {
        let mut agg = Aggregator::new(8, 2);
        agg.add_leaf(0);
        agg.add_leaf(1);
        agg.reserve(0b111);
        let step = agg.add_item(vec![0, 1, 2]);
        assert!(step.dropped.is_empty());
        // {0,1} was still running when the aggregate arrived.
        assert_eq!(agg.units(), vec![0b111]);
        let step = agg.job_done(vec![0, 1]);
        assert!(!step.kept);
        assert_eq!(agg.units(), vec![0b111]);
    }
}
