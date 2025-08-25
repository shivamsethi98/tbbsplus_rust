use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SidState { WaitingP1, P1Done, P2Done, ShareSubmitted }

#[test]
fn test_session_transitions() {
    let mut sessions: BTreeMap<u64, SidState> = BTreeMap::new();
    let sid = 42u64;

    // New session after PoK
    sessions.insert(sid, SidState::WaitingP1);
    assert_eq!(sessions.get(&sid), Some(&SidState::WaitingP1));

    // After Phase1 finalize
    sessions.insert(sid, SidState::P1Done);
    assert_eq!(sessions.get(&sid), Some(&SidState::P1Done));

    // After Phase2 finalize
    sessions.insert(sid, SidState::P2Done);
    assert_eq!(sessions.get(&sid), Some(&SidState::P2Done));

    // After share submitted
    sessions.insert(sid, SidState::ShareSubmitted);
    assert_eq!(sessions.get(&sid), Some(&SidState::ShareSubmitted));
}
