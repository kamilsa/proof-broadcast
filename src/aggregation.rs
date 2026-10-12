//! L2 aggregation: 2→1 recursive proof composition, pipelined with arrival.
//!
//! Every accepted subnet proof enters a pool. Whenever a prover worker is idle
//! and the pool holds two items, the pair is merged by one leanVM 2→1
//! recursion, which takes `aggregation_ms` (leanVM README: 0.287 s on an M4
//! Max). The merged item re-enters the pool; the job is done once one item
//! covers every subnet. The scheduler is pure; the node loop turns each
//! [`Job`] into a timer, which under Shadow advances simulated time only.

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

#[derive(Debug, Clone)]
pub struct Aggregator {
    subnets: usize,
    workers: usize,
    pool: Vec<Subnets>,
    running: usize,
    complete: bool,
}

impl Aggregator {
    pub fn new(subnets: usize, workers: usize) -> Self {
        Self {
            subnets,
            workers: workers.max(1),
            pool: Vec::new(),
            running: 0,
            complete: false,
        }
    }

    /// The proof for `subnet` became available. Returns the jobs to start now.
    pub fn add_leaf(&mut self, subnet: u16) -> Vec<Job> {
        self.add_item(vec![subnet])
    }

    /// A job finished, yielding `item` (its [`Job::merged`] subnets).
    pub fn job_done(&mut self, item: Subnets) -> Vec<Job> {
        self.running = self.running.saturating_sub(1);
        self.add_item(item)
    }

    fn add_item(&mut self, item: Subnets) -> Vec<Job> {
        if item.len() >= self.subnets {
            self.complete = true;
        }
        self.pool.push(item);
        self.schedule()
    }

    /// Start as many merges as idle workers allow, pairing the items covering
    /// the fewest subnets first so the recursion tree stays balanced.
    fn schedule(&mut self) -> Vec<Job> {
        let mut jobs = Vec::new();
        while !self.complete && self.running < self.workers && self.pool.len() >= 2 {
            // Stable: among equally sized items the newest are paired first.
            self.pool.sort_by_key(|item| std::cmp::Reverse(item.len()));
            let left = self.pool.pop().expect("pool has two items");
            let right = self.pool.pop().expect("pool has two items");
            self.running += 1;
            jobs.push(Job { left, right });
        }
        jobs
    }

    pub fn is_complete(&self) -> bool {
        self.complete
    }

    pub fn running(&self) -> usize {
        self.running
    }
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
            let jobs = if kind == 1 { agg.add_leaf(item[0]) } else { agg.job_done(item) };
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
        assert_eq!(agg.job_done(vec![3, 5]), vec![Job { left: vec![7], right: vec![0] }]);
    }

    #[test]
    fn complete_aggregate_covers_every_subnet() {
        let arrivals = [0u64; 16];
        let (_, jobs, _) = simulate(16, 3, 10, &arrivals);
        assert_eq!(jobs, 15);
        assert_eq!(subnet_list(&[0, 3, 12]), "0-3-12");
        assert_eq!(subnet_list(&[]), "none");
    }
}
