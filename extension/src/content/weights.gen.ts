// Written by bun corpus/train-weights.ts: do not edit by hand. Retrain after
// changing clusterFeatures (rationalize.ts) or the corpus, and commit the diff.
//
// The cluster model: each feature's log-odds weight and how many train
// clusters showed it. Fit on 79 clusters of the frozen corpus's train
// pages (56 logins, 23 not), L1 0.002, L2 0.01, weights under 0.05
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
  bias: -1.25,
  threshold: -0.41,
  features: {
    "autocomplete:login": [1.14, 25],
    "button:login": [0.23, 17],
    "button:named": [0.27, 54],
    "button:other": [-0.11, 24],
    "button:proceed": [1.07, 30],
    "controls:1": [0.11, 31],
    "controls:2-3": [0.32, 34],
    "controls:4-7": [-0.06, 11],
    "controls:8+": [-0.38, 3],
    "path:login": [0.44, 34],
    "role:identifier": [-0.17, 51],
    "role:named-password": [0.91, 38],
    "role:new-password": [0.16, 11],
    "role:password": [0.05, 35],
    "shape:identifier+password": [0.87, 26],
    "signal:none": [-1.18, 18],
    "title:login": [0.53, 25],
    "title:mfa": [0.46, 4],
    "title:reset": [0.38, 2],
    "unclaimed:0": [0.62, 57],
    "unclaimed:1": [-0.09, 9],
    "unclaimed:2+": [-0.32, 13],
    "words:auth": [0.65, 47],
    "words:change-password": [0.2, 3],
    "words:login": [0.5, 27],
    "words:newsletter": [-0.12, 2],
    "words:non-login": [-1.75, 17],
    "words:reset": [0.48, 9],
    "words:secret": [-0.3, 2],
    "words:sent-code": [-0.45, 4],
    "words:settings": [-0.06, 2],
  },
}
