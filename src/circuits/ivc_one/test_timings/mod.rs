mod aggregator_test;
mod ci_tests;
mod data_generators;
mod gh_runner_timing;
mod helpers;

use crate::{BlstrsEmulation, SelfEmulation};

pub(crate) type C = <BlstrsEmulation as SelfEmulation>::C;

pub(crate) const K: u32 = 19;
pub(crate) const K_INNER: u32 = 13;
