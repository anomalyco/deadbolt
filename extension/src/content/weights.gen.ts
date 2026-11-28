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
  bias: -1.6,
  threshold: -0.53,
  features: {
    "autocomplete:login": [1.13, 25],
    "button:login": [0.28, 18],
    "button:named": [0.21, 59],
    "button:other": [-0.09, 23],
    "button:proceed": [1.5, 32],
    "controls:2-3": [0.43, 35],
    "controls:8+": [-0.35, 3],
    "path:login": [0.61, 36],
    "role:identifier": [-0.24, 55],
    "role:named-password": [1.02, 39],
    "role:new-password": [0.22, 11],
    "role:otp": [0.09, 17],
    "role:password": [0.14, 36],
    "shape:identifier+password": [0.94, 27],
    "shape:one-field": [-0.07, 45],
    "signal:none": [-1.02, 18],
    "title:login": [0.64, 27],
    "title:mfa": [0.5, 4],
    "title:reset": [0.56, 2],
    "unclaimed:0": [0.44, 61],
    "unclaimed:1": [-0.07, 9],
    "unclaimed:2+": [-0.17, 13],
    "words:auth": [0.55, 51],
    "words:change-password": [0.23, 3],
    "words:login": [0.5, 29],
    "words:non-login": [-1.65, 17],
    "words:reset": [0.67, 10],
    "words:secret": [-0.3, 2],
    "words:sent-code": [-0.37, 4],
    "words:settings": [-0.09, 2],
  },
}
