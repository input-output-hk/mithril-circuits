use crate::{
    DST_ALBA_BIN, DST_ALBA_FINAL, DST_ALBA_ROUND, HashCPU, JubjubBase, LotteryIndex, PoseidonHash,
};
use dashu::{
    float::{FBig, round::mode::HalfEven},
    integer::UBig,
};

/// Binary arbitrary-precision float rounding to nearest (ties to even), like MPFR's default.
type BigFloat = FBig<HalfEven, 2>;

type F = JubjubBase;

type Seed = [u8; 16];

pub fn sample_uniform(hash: &F, n: u32) -> Option<u32> {
    debug_assert!(n > 0);

    let hash_bytes = hash.to_bytes_le();
    let hash: &Seed = hash_bytes[0..16].try_into().unwrap();

    // Computes the integer representation of hash modulo n when n is not a power of two.
    fn mod_not_power_of_2(hash: &Seed, n: u32) -> Option<u32> {
        let n = u128::from(n);

        // Equals floor(2^128 / n) since n is not a power of two.
        let d = u128::MAX / n;
        let i = u128::from_le_bytes(*hash);

        if i >= d * n {
            // We return here with probability (2^128 - d*n) / 2^128 < n / 2^128.
            // For n <= 2^40, this is less than 2^-88.
            None
        } else {
            Some((i % n) as u32)
        }
    }
    // Computes the integer representation of hash modulo n when n is a power of two.
    fn mod_power_of_2(hash: &Seed, n: u32) -> u32 {
        let bytes: [u8; 4] = hash[0..4].try_into().unwrap();
        u32::from_le_bytes(bytes) & (n - 1)
    }

    if n.is_power_of_two() {
        Some(mod_power_of_2(hash, n))
    } else {
        mod_not_power_of_2(hash, n)
    }
}

pub fn target(q: f64) -> u128 {
    debug_assert!(q >= 0.0);
    debug_assert!(q <= 1.0);

    // The product has at most 128 + 53 significant bits, so it is exact at 200 bits
    // of precision and truncation is exact.
    let max = BigFloat::from(u128::MAX).with_precision(200).value();
    let q = BigFloat::try_from(q).unwrap().with_precision(200).value();
    let t = max * q;
    let target: UBig = t.trunc().to_int().value().try_into().unwrap();
    target.try_into().unwrap()
}

pub fn sample_bernoulli_with_target(hash: &F, target: u128) -> bool {
    let hash_bytes = hash.to_bytes_le();
    let hash: &Seed = hash_bytes[0..16].try_into().unwrap();
    let i = u128::from_le_bytes(*hash);

    i < target
}

#[derive(Debug, Clone, Copy)]
pub struct Params {
    /// Number of prover set's elements
    pub proof_size: u32,
    /// Maximum number of retries to find a proof
    pub max_retries: u32,
    /// Maximum number of subtrees to search to find a proof
    pub search_width: u32,
    /// Probability that a tuple of element is a valid proof
    pub valid_proof_target: u128,
    /// Maximum number of DFS calls permitted to find a proof
    pub dfs_bound: u32,
}

impl Params {
    pub fn new(
        proof_size: u32,
        max_retries: u32,
        search_width: u32,
        valid_proof_probability: f64,
        dfs_bound: u32,
    ) -> Self {
        let valid_proof_target = target(valid_proof_probability);
        Self {
            proof_size,
            max_retries,
            search_width,
            valid_proof_target,
            dfs_bound,
        }
    }
}

#[derive(Debug, Clone)]
/// Type of dataset's elements with an optional index
pub struct Element {
    /// Set element data
    pub data: LotteryIndex,
    /// ID of the element
    pub index: Option<u64>,
}

impl Element {
    /// Create a new element for given data and index
    pub fn new(data: LotteryIndex, index: Option<u64>) -> Self {
        Self { data, index }
    }

    pub fn to_field(&self) -> F {
        F::from(self.data as u64)
    }
}

#[derive(Debug, Clone)]
pub struct Round {
    /// Numbers of retries done so far
    pub retry_counter: u32,
    /// Index of the current subtree being searched
    pub search_counter: u32,
    /// Candidate element sequence
    pub element_sequence: Vec<Element>,
    /// Candidate round hash
    pub hash: F,
    /// Candidate round id, i.e. round hash mapped to [1, set_size]
    pub id: u32,
    /// Approximate size of prover set to lower bound
    pub set_size: u32,
}

impl Round {
    pub fn new(retry_counter: u32, search_counter: u32, set_size: u32) -> Option<Self> {
        let hash = PoseidonHash::hash(&[
            DST_ALBA_ROUND,
            F::from(retry_counter as u64),
            F::from(search_counter as u64),
        ]);
        let id_opt = sample_uniform(&hash, set_size);
        id_opt.map(|id| Self {
            retry_counter,
            search_counter,
            element_sequence: Vec::new(),
            hash,
            id,
            set_size,
        })
    }

    pub fn update(round: &Round, element: &Element) -> Option<Self> {
        let mut element_sequence = round.element_sequence.clone();
        element_sequence.push(element.clone());

        let round_hash = PoseidonHash::hash(&[round.hash, element.to_field()]);
        let id_opt = sample_uniform(&round_hash, round.set_size);
        id_opt.map(|id| Self {
            retry_counter: round.retry_counter,
            search_counter: round.search_counter,
            element_sequence,
            hash: round_hash,
            id,
            set_size: round.set_size,
        })
    }
}

/// Centralized Telescope proof
#[derive(Debug, Clone)]
pub struct Proof {
    /// Numbers of retries done to find the proof
    pub retry_counter: u32,
    /// Index of the searched subtree to find the proof
    pub search_counter: u32,
    /// Sequence of elements from prover's set
    pub element_sequence: Vec<Element>,
}

impl Proof {
    fn bin_hash(set_size: u32, retry_counter: u32, element: &Element) -> Option<u32> {
        let hash = PoseidonHash::hash(&[
            DST_ALBA_BIN,
            F::from(retry_counter as u64),
            element.to_field(),
        ]);
        sample_uniform(&hash, set_size)
    }

    fn proof_hash(valid_proof_target: u128, r: &Round) -> bool {
        let hash = PoseidonHash::hash(&[DST_ALBA_FINAL, r.hash]);
        sample_bernoulli_with_target(&hash, valid_proof_target)
    }

    /// Indexed proving algorithm, returns the total number of DFS calls done
    /// to find a proof and `Some(proof)` if found within `params.dfs_bound` calls
    /// of DFS, otherwise `None`
    fn prove_index(
        set_size: u32,
        params: &Params,
        prover_set: &[Element],
        retry_counter: u32,
    ) -> (u32, Option<Self>) {
        // Initialize set_size bins
        let mut bins = Vec::with_capacity(set_size as usize);
        for _ in 0..set_size {
            bins.push(Vec::new());
        }

        // Take only up to 2*set_size elements for efficiency and fill the bins with them
        for element in prover_set.iter().take(set_size.saturating_mul(2) as usize) {
            match Self::bin_hash(set_size, retry_counter, element) {
                Some(bin_index) => {
                    bins[bin_index as usize].push(element.clone());
                }
                None => return (0, None),
            }
        }

        // Run the DFS algorithm on up to params.search_width different trees
        let mut step = 0;
        for search_counter in 0..params.search_width {
            // If DFS was called more than dfs_bound times, abort this retry
            if step >= params.dfs_bound {
                return (step, None);
            }
            // Initialize new round
            if let Some(r) = Round::new(retry_counter, search_counter, set_size) {
                // Run DFS on such round, incrementing step
                let (dfs_calls, proof_opt) = Self::dfs(params, &bins, &r, step.saturating_add(1));
                // Return proof if found
                if proof_opt.is_some() {
                    return (dfs_calls, proof_opt);
                }
                // Update step, that is the number of DFS calls
                step = dfs_calls;
            }
        }
        (step, None)
    }

    /// Depth-First Search (DFS) algorithm which goes through all potential
    /// round candidates and returns the total number of recursive DFS calls
    /// done and, if not found under params.dfs_bound calls, None otherwise
    /// `Some(Proof)`, that is the first "round", i.e. the first proof candidate,
    /// Round{retry_counter, search_counter, x_1, ..., x_u)} such that:
    /// - ∀i ∈ [0, u-1], bin_hash(x_i+1) ∈ bins[round_hash(...round_hash(round_hash(v, t), x_1), ..., x_i)]
    /// - proof_hash(round_hash(... round_hash((round_hash(v, t), x_1), ..., x_u)) = true
    fn dfs(
        params: &Params,
        bins: &[Vec<Element>],
        round: &Round,
        mut step: u32,
    ) -> (u32, Option<Self>) {
        // If current round comprises params.proof_size elements and satisfies
        // the proof_hash check, return it cast as a Proof
        if round.element_sequence.len() as u32 == params.proof_size {
            let proof_opt = if Self::proof_hash(params.valid_proof_target, round) {
                Some(Self {
                    retry_counter: round.retry_counter,
                    search_counter: round.search_counter,
                    element_sequence: round.element_sequence.clone(),
                })
            } else {
                None
            };
            return (step, proof_opt);
        }

        // For each element in bin numbered id
        for element in &bins[round.id as usize] {
            // If DFS was called more than params.dfs_bound times, abort this round
            if step == params.dfs_bound {
                return (step, None);
            }
            // Update round with such element
            if let Some(r) = Round::update(round, element) {
                // Run DFS on updated round, incrementing step
                let (dfs_calls, proof_opt) = Self::dfs(params, bins, &r, step.saturating_add(1));
                // Return proof if found
                if proof_opt.is_some() {
                    return (dfs_calls, proof_opt);
                }
                // Update step, i.e. is the number of DFS calls
                step = dfs_calls;
            }
        }
        // If no proof was found, return number of steps and None
        (step, None)
    }

    pub fn prove_routine(
        set_size: u32,
        params: &Params,
        prover_set: &[Element],
    ) -> (u32, Option<Self>) {
        let mut steps: u32 = 0;

        // Run prove_index up to max_retries times
        for retry_counter in 0..params.max_retries {
            let (dfs_calls, proof_opt) = Self::prove_index(
                set_size,
                params,
                prover_set,
                retry_counter.saturating_add(1),
            );
            steps = steps.saturating_add(dfs_calls);
            if proof_opt.is_some() {
                return (steps, proof_opt);
            }
        }
        (steps, None)
    }

    pub fn verify(&self, set_size: u32, params: &Params) -> bool {
        if self.search_counter >= params.search_width
            || self.retry_counter >= params.max_retries
            || self.element_sequence.len() as u32 != params.proof_size
        {
            return false;
        }

        // Initialise a round with given retry and search counters
        let Some(mut round) = Round::new(self.retry_counter, self.search_counter, set_size) else {
            return false;
        };

        // For each element in the proof's sequence
        for element in &self.element_sequence {
            // Retrieve the bin id associated to this new element
            let Some(bin_id) = Self::bin_hash(set_size, self.retry_counter, element) else {
                return false;
            };
            // Check that the new element was chosen correctly
            // i.e. that we chose the new element such that its bin id equals the round id
            if round.id == bin_id {
                match Round::update(&round, element) {
                    Some(r) => round = r,
                    None => return false,
                }
            } else {
                return false;
            }
        }
        Self::proof_hash(params.valid_proof_target, &round)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference targets computed by the original rug/MPFR implementation;
    /// the dashu-based implementation must reproduce them bit-for-bit.
    #[test]
    fn test_target_mpfr_reference_vectors() {
        assert_eq!(target(0.5), 170141183460469231731687303715884105727);
        assert_eq!(
            target(0.6180339887498949),
            210306068529402891650266558847000772607
        );
        assert_eq!(target(1.0), 340282366920938463463374607431768211455);
        assert_eq!(target(0.0), 0);
    }

    #[test]
    fn test_alba_proof() {
        let params = Params::new(55, 32, 4374, 0.001136217032367627, 788581);
        let set_size = 614;
        let prover_set_size = 3000;
        let prover_set = (0..prover_set_size)
            .map(|i| Element::new(i + 1, None))
            .collect::<Vec<_>>();
        let (steps, proof_opt) = Proof::prove_routine(set_size, &params, &prover_set);
        println!("steps: {}", steps);
        assert!(proof_opt.unwrap().verify(set_size, &params))
    }
}
