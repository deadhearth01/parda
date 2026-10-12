//! Property tests for the SSE parser: arbitrary bytes never panic, and any
//! split of a valid stream yields the same events.

use bytes::BytesMut;
use parda_proxy::{SseEvent, parse_sse, serialize};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..2000)) {
        let mut buf = BytesMut::from(&bytes[..]);
        let _ = parse_sse(&mut buf);
    }

    #[test]
    fn chunking_does_not_change_events(
        datas in proptest::collection::vec("[^\r\n]{0,40}", 1..12),
        cuts in proptest::collection::vec(0usize..2000, 0..20),
    ) {
        let events: Vec<SseEvent> = datas
            .iter()
            .enumerate()
            .map(|(i, d)| SseEvent::new((i % 2 == 0).then_some("delta"), d.clone()))
            .collect();
        let wire: Vec<u8> = events.iter().flat_map(|e| serialize(e).to_vec()).collect();
        let mut pts: Vec<usize> = cuts.into_iter().map(|c| c.min(wire.len())).collect();
        pts.sort_unstable();
        pts.dedup();
        let mut buf = BytesMut::new();
        let mut got = Vec::new();
        let mut prev = 0;
        for p in pts.into_iter().chain([wire.len()]) {
            buf.extend_from_slice(&wire[prev..p]);
            got.extend(parse_sse(&mut buf));
            prev = p;
        }
        prop_assert!(buf.is_empty());
        let got: Vec<(Option<String>, String)> = got.into_iter().map(|e| (e.event, e.data)).collect();
        let want: Vec<(Option<String>, String)> = events.into_iter().map(|e| (e.event, e.data)).collect();
        prop_assert_eq!(got, want);
    }
}
