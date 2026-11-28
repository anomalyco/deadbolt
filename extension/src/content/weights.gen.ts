// Written by bun corpus/train-weights.ts: do not edit by hand. Retrain after
// changing clusterFeatures (rationalize.ts) or the corpus, and commit the diff.
//
// The cluster model: each feature's log-odds weight and how many train
// clusters showed it. Fit on 90 clusters of the frozen corpus's train
// pages (62 logins, 28 not), L1 0.002, L2 0.01, weights under 0.05
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
  bias: -1.74,
  threshold: -0.57,
  features: {
    "autocomplete:login": [1.23, 25],
    "button:login": [0.53, 21],
    "button:proceed": [1.6, 34],
    "controls:2-3": [0.53, 39],
    "controls:4-7": [-0.12, 12],
    "controls:8+": [-0.31, 3],
    "path:login": [0.29, 40],
    "role:identifier": [-0.23, 62],
    "role:named-password": [0.85, 43],
    "role:new-password": [0.45, 11],
    "role:otp": [0.2, 17],
    "shape:identifier+password": [0.74, 31],
    "signal:none": [-1.03, 19],
    "title:login": [0.71, 28],
    "title:mfa": [0.45, 4],
    "title:reset": [0.49, 2],
    "title:signup": [0.2, 6],
    "unclaimed:0": [0.57, 67],
    "unclaimed:2+": [-0.41, 14],
    "words:auth": [0.56, 56],
    "words:change-password": [0.18, 3],
    "words:login": [0.72, 33],
    "words:non-login": [-1.57, 18],
    "words:offer": [-0.16, 4],
    "words:reset": [0.62, 10],
    "words:secret": [-0.28, 2],
    "words:sent-code": [-0.22, 4],
  },
}
