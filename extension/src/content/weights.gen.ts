// Written by bun corpus/train-weights.ts: do not edit by hand. Retrain after
// changing clusterFeatures (rationalize.ts) or the corpus, and commit the diff.
//
// The cluster model: each feature's log-odds weight and how many train
// clusters showed it. Fit on 71 clusters of the frozen corpus's train
// pages (48 logins, 23 not), L1 0.002, L2 0.01, weights under 0.05
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
  bias: -1.03,
  threshold: 0.04,
  features: {
    "autocomplete:login": [1.47, 25],
    "button:login": [0.53, 17],
    "button:named": [0.53, 48],
    "button:other": [-0.34, 22],
    "button:proceed": [0.36, 25],
    "button:signup": [-0.32, 7],
    "controls:2-3": [0.46, 30],
    "controls:8+": [-0.72, 3],
    "path:login": [0.45, 34],
    "path:settings": [-0.07, 4],
    "path:signup": [-0.06, 6],
    "role:new-password": [0.33, 10],
    "shape:code-length": [-0.29, 13],
    "shape:identifier+password": [0.76, 21],
    "signal:none": [-1.8, 17],
    "title:login": [0.95, 25],
    "title:mfa": [0.87, 4],
    "title:reset": [0.61, 2],
    "title:signup": [0.28, 5],
    "unclaimed:0": [0.42, 50],
    "unclaimed:2+": [-0.25, 12],
    "words:change-password": [0.49, 3],
    "words:login": [0.44, 24],
    "words:offer": [-0.21, 3],
    "words:reset": [0.76, 9],
    "words:secret": [-0.66, 2],
    "words:sent-code": [-0.94, 4],
    "words:settings": [-0.14, 2],
  },
}
