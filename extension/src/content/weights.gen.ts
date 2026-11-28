// Written by bun corpus/train-weights.ts: do not edit by hand. Retrain after
// changing clusterFeatures (rationalize.ts) or the corpus, and commit the diff.
//
// The cluster model: each feature's log-odds weight and how many train
// clusters showed it. Fit on 83 clusters of the frozen corpus's train
// pages (58 logins, 25 not), L1 0.002, L2 0.01, weights under 0.05
// dropped. A cluster whose summed odds fall under the threshold isn't a
// login form.

export interface Weights {
  version: 1
  bias: number
  threshold: number
  /** Feature id to [weight, train support]. */
  features: Readonly<Record<string, readonly [weight: number, support: number]>>
}

export const WEIGHTS: Weights = {
  version: 1,
  bias: -1.46,
  threshold: -0.45,
  features: {
    "autocomplete:login": [1.22, 25],
    "button:login": [0.34, 18],
    "button:named": [0.08, 58],
    "button:proceed": [1.61, 31],
    "controls:2-3": [0.36, 35],
    "controls:8+": [-0.41, 3],
    "path:login": [0.25, 37],
    "role:identifier": [-0.25, 55],
    "role:named-password": [1.02, 39],
    "role:new-password": [0.2, 11],
    "role:otp": [0.13, 17],
    "role:password": [0.12, 36],
    "shape:identifier+password": [0.96, 27],
    "signal:none": [-1.16, 18],
    "title:login": [0.15, 28],
    "title:mfa": [0.47, 4],
    "title:reset": [0.49, 2],
    "unclaimed:0": [0.5, 61],
    "unclaimed:1": [-0.09, 9],
    "unclaimed:2+": [-0.21, 13],
    "words:auth": [0.52, 51],
    "words:change-password": [0.22, 3],
    "words:login": [0.81, 29],
    "words:newsletter": [-0.05, 2],
    "words:non-login": [-1.66, 17],
    "words:reset": [0.63, 10],
    "words:secret": [-0.32, 2],
    "words:sent-code": [-0.3, 4],
    "words:settings": [-0.09, 2],
  },
}
