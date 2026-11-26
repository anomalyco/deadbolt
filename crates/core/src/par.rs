//! Data-parallel helpers: split across the machine's cores in native builds,
//! in order on wasm32, which has no threads.

/// `f` over `items`, results in order. Each core takes a run of items, so
/// pass few, heavy items (frames to open), not many light ones.
pub fn map<T: Sync, U: Send>(items: &[T], f: impl Fn(&T) -> U + Sync) -> Vec<U> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        let threads = std::thread::available_parallelism()
            .map_or(1, std::num::NonZero::get)
            .min(items.len());
        if threads > 1 {
            let f = &f;
            return std::thread::scope(|s| {
                let runs: Vec<_> = items
                    .chunks(items.len().div_ceil(threads))
                    .map(|run| s.spawn(move || run.iter().map(f).collect::<Vec<_>>()))
                    .collect();
                runs.into_iter()
                    .flat_map(|run| run.join().unwrap_or_else(|e| std::panic::resume_unwind(e)))
                    .collect()
            });
        }
    }
    items.iter().map(f).collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn results_keep_their_order() {
        let items: Vec<u32> = (0..1000).collect();
        assert_eq!(
            super::map(&items, |i| i * 2),
            items.iter().map(|i| i * 2).collect::<Vec<_>>()
        );
        assert!(super::map(&[] as &[u32], |i| *i).is_empty());
    }
}
