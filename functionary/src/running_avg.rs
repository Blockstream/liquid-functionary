//{{ Liquid }}
//Copyright (C) {{ 2015,2016,2017,2018 }}  {{ Blockstream }}

//This program is free software: you can redistribute it and/or modify
//it under the terms of the GNU Affero General Public License as published by
//the Free Software Foundation, either version 3 of the License, or
//(at your option) any later version.

//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//GNU Affero General Public License for more details.

//You should have received a copy of the GNU Affero General Public License
//along with this program.  If not, see <http://www.gnu.org/licenses/>.


//! # RunningAverage
//! Class to maintain an Exponentially weighted moving average. The running mean
/// is conservative by starting at 0 and ramp up as more samples are added. This
/// is to avoid early outliers to have disproportional weight.

/// maintains the state for an Exponentially weighted moving average
#[derive(Clone, PartialEq, Debug)]
pub struct RunningAverage {
    mean: f64,
}

impl RunningAverage {
    /// add another sample to the running mean. Each sample will have a 10%
    /// weight. The initial state is 0, so there will be an early bias towards
    /// 0.
    pub fn sample(&mut self, val: f64) {
        let factor = 0.1;
        self.mean = self.mean * (1.0 - factor) + (val * factor);
    }

    /// returns the current running mean. If there's only been a few samples,
    /// it will tend to be lower.
    pub fn mean(&self) -> f64 {
        self.mean
    }

    /// create an empty running average state, initialized to 0.0
    pub fn new() -> RunningAverage {
        RunningAverage { mean: 0.0 }
    }
}

#[test]
fn initial_value() {
    // the initial mean value should be 0
    let t = RunningAverage::new();
    assert!(t.mean() == 0.0, "mean is: {}", t.mean());
}

#[test]
fn initial_weight() {
    // if we only have a single sample, the value is 10% of it.
    let mut t = RunningAverage::new();
    t.sample(100.0);
    assert!((t.mean() - 10.0).abs() < 0.01, "mean is: {}", t.mean());
}

#[test]
fn early_weight() {
    // if we only have two samples, the mean is the mean of those two
    let mut t = RunningAverage::new();
    t.sample(100.0);
    t.sample(100.0);
    assert!((t.mean() - 19.0).abs() < 0.01, "mean is: {}", t.mean());
}

#[test]
fn average() {
    // with many alternating samples, the running average should be close to the
    // middle
    let mut t = RunningAverage::new();
    for _ in 0..100 {
        t.sample(5.0);
        t.sample(15.0);
    }
    assert!((t.mean() - 10.0).abs() < 1.0, "mean is: {}", t.mean());
}
