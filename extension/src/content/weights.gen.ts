// Written by bun corpus/train-weights.ts: do not edit by hand. Retrain after
// changing clusterFeatures (rationalize.ts) or the corpus, and commit the diff.
//
// The cluster model: each feature's log-odds weight and how many train
// clusters showed it. Fit on 90 clusters of the frozen corpus's train
// pages (63 logins, 27 not), L1 0.002, L2 0.01, weights under 0.05
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
  bias: -1.81,
  threshold: -0.18,
  features: {
    "autocomplete:login": [1.15, 26],
    "button:login": [0.32, 21],
    "button:named": [0.05, 66],
    "button:proceed": [1.52, 35],
    "controls:2-3": [0.41, 39],
    "controls:8+": [-0.33, 3],
    "page:other-code-forms": [-0.75, 2],
    "path:login": [0.81, 39],
    "role:named-password": [1.03, 42],
    "role:new-password": [0.2, 11],
    "role:password": [0.24, 39],
    "shape:code-length": [-0.16, 15],
    "shape:identifier+password": [0.88, 30],
    "signal:none": [-1.32, 18],
    "title:login": [0.6, 28],
    "title:mfa": [0.47, 4],
    "title:reset": [0.47, 2],
    "unclaimed:0": [0.33, 68],
    "unclaimed:2+": [-0.13, 13],
    "words:auth": [0.74, 56],
    "words:change-password": [0.17, 3],
    "words:login": [0.49, 33],
    "words:mfa": [0.15, 7],
    "words:non-login": [-1.43, 18],
    "words:offer": [-0.13, 4],
    "words:reset": [0.57, 10],
    "words:secret": [-0.24, 2],
    "words:sent-code": [-0.12, 4],
    "words:settings": [-0.09, 2],
  },
}
