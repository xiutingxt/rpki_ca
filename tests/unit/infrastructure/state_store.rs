use super::*;
use crate::ca::state::CaStateStore;
use std::{sync::mpsc, time::Duration};

#[test]
fn concurrent_lock_waits_instead_of_returning_ca_busy() {
    let directory = tempfile::tempdir().unwrap();
    let store = LocalStateStore::new(directory.path());
    let first = store.lock().unwrap();
    let (started_tx, started_rx) = mpsc::channel();
    let (acquired_tx, acquired_rx) = mpsc::channel();

    let contender = store.clone();
    let thread = std::thread::spawn(move || {
        started_tx.send(()).unwrap();
        let _second = contender.lock().unwrap();
        acquired_tx.send(()).unwrap();
    });

    started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    assert!(
        acquired_rx
            .recv_timeout(Duration::from_millis(100))
            .is_err()
    );

    drop(first);
    acquired_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    thread.join().unwrap();
}
