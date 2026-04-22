// SPDX-License-Identifier: GPL-2.0-or-later
//
// tests/unit/test_profile.rs — Rust port of unit/test-profile.c
//
// Comprehensive unit tests for the `bluetoothd::profile` module, verifying:
// - `BtdProfile` construction with default field values
// - Priority constant ordering (`LOW < MEDIUM < HIGH`)
// - `btd_profile_sort_list`: stable descending priority sort, `after_services`
//   dependency resolution, cycle termination, and randomised fuzz verification
// - `BtdProfileUuidCb`: UUID matching callback creation and invocation
// - Multiple profile configurations with varying parameters
//
// Every test function maps to an identically-named test or test-case in the
// original C file (`unit/test-profile.c`), with additional Rust-idiomatic tests
// for registration, lifecycle, and edge cases.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use bluetoothd::profile::{
    BTD_PROFILE_PRIORITY_HIGH, BTD_PROFILE_PRIORITY_LOW, BTD_PROFILE_PRIORITY_MEDIUM, BtdProfile,
    BtdProfileUuidCb, btd_profile_sort_list,
};
use bluez_shared::util::queue::Queue;
use rand::Rng;

// ============================================================================
// Helper: Create a profile with specified fields
// ============================================================================

/// Construct an `Arc<BtdProfile>` with the given name, priority, optional
/// remote UUID, and optional list of `after_services` dependency UUIDs.
///
/// This is the Rust analogue of the C `SORT_PROFILE(...)` macro from
/// `unit/test-profile.c` (line 22), adapted for the Rust `BtdProfile` API
/// which uses `String` fields instead of `const char *`.
fn make_profile(
    name: &str,
    priority: i32,
    remote_uuid: Option<&str>,
    after_services: Vec<&str>,
) -> Arc<BtdProfile> {
    let mut p = BtdProfile::new(name);
    p.priority = priority;
    p.remote_uuid = remote_uuid.map(|s| s.to_owned());
    p.after_services = after_services.into_iter().map(|s| s.to_owned()).collect();
    Arc::new(p)
}

/// Construct an `Arc<BtdProfile>` with both local and remote UUIDs set.
fn make_profile_full(
    name: &str,
    priority: i32,
    local_uuid: Option<&str>,
    remote_uuid: Option<&str>,
    after_services: Vec<&str>,
) -> Arc<BtdProfile> {
    let mut p = BtdProfile::new(name);
    p.priority = priority;
    p.local_uuid = local_uuid.map(|s| s.to_owned());
    p.remote_uuid = remote_uuid.map(|s| s.to_owned());
    p.after_services = after_services.into_iter().map(|s| s.to_owned()).collect();
    Arc::new(p)
}

// ============================================================================
// Helper: Property-based sort verification
// ============================================================================

/// Verify that a sorted profile slice satisfies the invariants enforced by
/// `btd_profile_sort_list`:
///
/// 1. **Length** — the slice contains exactly `expected_len` profiles.
/// 2. **No duplicates** — every element is a distinct `Arc` allocation.
/// 3. **Priority ordering** — for any adjacent pair where neither has
///    `after_services`, the earlier entry has priority ≥ the later one.
/// 4. **Dependency constraint** — if profile P lists UUID U in its
///    `after_services` and some profile Q has `remote_uuid` or `local_uuid`
///    matching U (case-insensitive), then Q appears before P.
///
/// Ported from `check_sort()` in `unit/test-profile.c` (lines 57–111).
fn check_sort_properties(profiles: &[Arc<BtdProfile>], expected_len: usize) {
    // 1. Length
    assert_eq!(
        profiles.len(),
        expected_len,
        "sorted list length mismatch: expected {expected_len}, got {}",
        profiles.len()
    );

    // 2. No duplicates (pointer identity via Arc::ptr_eq)
    for i in 0..profiles.len() {
        for j in 0..i {
            assert!(
                !Arc::ptr_eq(&profiles[i], &profiles[j]),
                "duplicate entry detected at positions {j} and {i}: both are '{}'",
                profiles[i].name
            );
        }
    }

    // 3. Priority ordering for profiles without after_services
    for i in 1..profiles.len() {
        let prev = &profiles[i - 1];
        let curr = &profiles[i];

        // Skip pairs where either profile has dependency constraints —
        // their positions are governed by the topological pass, not pure
        // priority ordering.
        if !prev.after_services.is_empty() || !curr.after_services.is_empty() {
            continue;
        }

        assert!(
            prev.priority >= curr.priority,
            "priority order violation at positions {} and {}: '{}' (pri={}) should not \
             precede '{}' (pri={})",
            i - 1,
            i,
            prev.name,
            prev.priority,
            curr.name,
            curr.priority,
        );
    }

    // 4. After_services dependency constraint
    for i in 0..profiles.len() {
        if profiles[i].after_services.is_empty() {
            continue;
        }

        for dep_uuid in &profiles[i].after_services {
            let dep_lower = dep_uuid.to_lowercase();

            for j in 0..profiles.len() {
                let has_match = profiles[j]
                    .remote_uuid
                    .as_ref()
                    .map(|u| u.to_lowercase() == dep_lower)
                    .unwrap_or(false)
                    || profiles[j]
                        .local_uuid
                        .as_ref()
                        .map(|u| u.to_lowercase() == dep_lower)
                        .unwrap_or(false);

                if has_match {
                    assert!(
                        j < i,
                        "after_services violation: '{}' (pos {i}) depends on UUID '{dep_uuid}' \
                         which matches '{}' at pos {j} — dependency must appear earlier",
                        profiles[i].name,
                        profiles[j].name,
                    );
                }
            }
        }
    }
}

// ============================================================================
// Helper: Queue-based index shuffle
// ============================================================================

/// Shuffle a sequence of `count` indices `[0, 1, …, count-1]` using the same
/// algorithm as `shuffle_list()` in `unit/test-profile.c` (lines 113–122):
/// for each of `count` iterations, pick a random position, remove the element
/// at that position, and re-insert it at the tail.
///
/// This function exercises all required `Queue<T>` members:
/// - `Queue::new()` — create the index queue
/// - `Queue::push_tail()` — populate and re-insert elements
/// - `Queue::len()` — bounds for random position
/// - `Queue::get()` — peek at an element by index
/// - `Queue::remove()` — extract an element by value (usize: PartialEq)
/// - `Queue::iter()` — collect the shuffled order
fn shuffle_indices(count: usize, rng: &mut impl Rng) -> Vec<usize> {
    let mut queue: Queue<usize> = Queue::new();

    // Populate with sequential indices
    for i in 0..count {
        queue.push_tail(i);
    }

    // Perform count random remove-and-push-tail operations
    let len = queue.len();
    for _ in 0..len {
        let pos = rng.gen_range(0..queue.len());
        let idx = *queue.get(pos).expect("get() at valid position must succeed");
        queue.remove(&idx);
        queue.push_tail(idx);
    }

    // Collect shuffled order via iter()
    queue.iter().copied().collect()
}

// ============================================================================
// test_profile_creation — BtdProfile::new() default values
// ============================================================================

/// Verify that `BtdProfile::new()` initialises all fields to their documented
/// defaults: priority = MEDIUM, bearer = 0 (ANY), no UUIDs, empty
/// `after_services`, all booleans false.
#[test]
fn test_profile_creation() {
    let p = BtdProfile::new("TestProfile");

    assert_eq!(p.name, "TestProfile");
    assert_eq!(p.priority, BTD_PROFILE_PRIORITY_MEDIUM);
    assert_eq!(p.bearer, 0);
    assert!(p.local_uuid.is_none());
    assert!(p.remote_uuid.is_none());
    assert!(!p.auto_connect);
    assert!(!p.external);
    assert!(!p.experimental);
    assert!(!p.testing);
    assert!(p.after_services.is_empty());
}

// ============================================================================
// test_profile_priority_constants — LOW < MEDIUM < HIGH ordering
// ============================================================================

/// Verify the priority constants satisfy the ordering invariant relied upon
/// by `btd_profile_sort_list`.  Exact values must match C `src/profile.h`:
/// `LOW = 0`, `MEDIUM = 1`, `HIGH = 2`.
#[test]
fn test_profile_priority_constants() {
    // Exact values matching C: LOW=0, MEDIUM=1, HIGH=2
    assert_eq!(BTD_PROFILE_PRIORITY_LOW, 0);
    assert_eq!(BTD_PROFILE_PRIORITY_MEDIUM, 1);
    assert_eq!(BTD_PROFILE_PRIORITY_HIGH, 2);

    // Verify ordering through actual sort behaviour: [LOW, MEDIUM, HIGH] input
    // must produce [HIGH, MEDIUM, LOW] output after descending-priority sort.
    let low = make_profile("Low", BTD_PROFILE_PRIORITY_LOW, None, vec![]);
    let med = make_profile("Med", BTD_PROFILE_PRIORITY_MEDIUM, None, vec![]);
    let high = make_profile("High", BTD_PROFILE_PRIORITY_HIGH, None, vec![]);

    let mut profiles = vec![low, med, high];
    btd_profile_sort_list(&mut profiles);

    assert_eq!(profiles[0].name, "High", "HIGH must sort first");
    assert_eq!(profiles[1].name, "Med", "MEDIUM must sort second");
    assert_eq!(profiles[2].name, "Low", "LOW must sort last");
}

// ============================================================================
// test_sort_empty — Edge case: sorting an empty slice
// ============================================================================

/// Verify that `btd_profile_sort_list` handles an empty slice without panic.
#[test]
fn test_sort_empty() {
    let mut profiles: Vec<Arc<BtdProfile>> = Vec::new();
    btd_profile_sort_list(&mut profiles);
    assert!(profiles.is_empty());
}

// ============================================================================
// test_sort_single — Edge case: sorting a single-element slice
// ============================================================================

/// Verify that sorting a single profile is a no-op.
#[test]
fn test_sort_single() {
    let p = make_profile("Solo", BTD_PROFILE_PRIORITY_HIGH, Some("S"), vec![]);
    let mut profiles = vec![p.clone()];
    btd_profile_sort_list(&mut profiles);

    assert_eq!(profiles.len(), 1);
    assert!(Arc::ptr_eq(&profiles[0], &p));
}

// ============================================================================
// test_sort_priority — Sort by descending priority (stable)
// ============================================================================

/// Ported from "Sort Priority" in `unit/test-profile.c` (lines 27–38).
///
/// Six profiles with priorities `[1, 1, 2, 0, 2, 0]` are sorted. The expected
/// output is a stable descending sort: `[2, 2, 1, 1, 0, 0]` preserving
/// insertion order among equal priorities.
///
/// C equivalence:
/// - `SORT_PROFILE(3, .priority = 1)` → profile "P0" (pri=1), expected pos 3
/// - `SORT_PROFILE(4, .priority = 1)` → profile "P1" (pri=1), expected pos 4
/// - `SORT_PROFILE(1, .priority = 2)` → profile "P2" (pri=2), expected pos 1
/// - `SORT_PROFILE(5, .priority = 0)` → profile "P3" (pri=0), expected pos 5
/// - `SORT_PROFILE(2, .priority = 2)` → profile "P4" (pri=2), expected pos 2
/// - `SORT_PROFILE(6, .priority = 0)` → profile "P5" (pri=0), expected pos 6
#[test]
fn test_sort_priority() {
    let p0 = make_profile("P0", 1, None, vec![]);
    let p1 = make_profile("P1", 1, None, vec![]);
    let p2 = make_profile("P2", 2, None, vec![]);
    let p3 = make_profile("P3", BTD_PROFILE_PRIORITY_LOW, None, vec![]);
    let p4 = make_profile("P4", BTD_PROFILE_PRIORITY_HIGH, None, vec![]);
    let p5 = make_profile("P5", BTD_PROFILE_PRIORITY_LOW, None, vec![]);

    let mut profiles = vec![p0.clone(), p1.clone(), p2.clone(), p3.clone(), p4.clone(), p5.clone()];

    btd_profile_sort_list(&mut profiles);

    // Property-based verification
    check_sort_properties(&profiles, 6);

    // Exact position verification: priority 2 first (stable order P2, P4),
    // then priority 1 (P0, P1), then priority 0 (P3, P5).
    assert_eq!(profiles[0].name, "P2", "pos 0: expected P2 (pri=2)");
    assert_eq!(profiles[1].name, "P4", "pos 1: expected P4 (pri=2)");
    assert_eq!(profiles[2].name, "P0", "pos 2: expected P0 (pri=1)");
    assert_eq!(profiles[3].name, "P1", "pos 3: expected P1 (pri=1)");
    assert_eq!(profiles[4].name, "P3", "pos 4: expected P3 (pri=0)");
    assert_eq!(profiles[5].name, "P5", "pos 5: expected P5 (pri=0)");
}

// ============================================================================
// test_sort_after_service — Dependency ordering via after_services
// ============================================================================

/// Ported from "Sort After Service" in `unit/test-profile.c` (lines 39–54).
///
/// Six profiles with `after_services` dependencies. The sort must place
/// each profile after all profiles whose UUIDs appear in its `after_services`
/// list. The "invalid" UUID matches no profile and is ignored.
///
/// Input profiles:
///   A (pri=2, remote="A")
///   B (pri=2, remote="B", after=["A"])
///   C (pri=1, remote="C", after=["invalid"])
///   D (pri=1, remote="D", after=["B"])
///   E (pri=1, remote="E", after=["A"])
///   F (pri=0, remote="F")
#[test]
fn test_sort_after_service() {
    let a = make_profile("A", BTD_PROFILE_PRIORITY_HIGH, Some("A"), vec![]);
    let b = make_profile("B", BTD_PROFILE_PRIORITY_HIGH, Some("B"), vec!["A"]);
    let c = make_profile("C", BTD_PROFILE_PRIORITY_MEDIUM, Some("C"), vec!["invalid"]);
    let d = make_profile("D", BTD_PROFILE_PRIORITY_MEDIUM, Some("D"), vec!["B"]);
    let e = make_profile("E", BTD_PROFILE_PRIORITY_MEDIUM, Some("E"), vec!["A"]);
    let f = make_profile("F", BTD_PROFILE_PRIORITY_LOW, Some("F"), vec![]);

    let mut profiles = vec![a.clone(), b.clone(), c.clone(), d.clone(), e.clone(), f.clone()];

    btd_profile_sort_list(&mut profiles);

    // Property-based verification: all after_services constraints satisfied
    check_sort_properties(&profiles, 6);

    // A must be first — highest priority, no dependencies
    assert_eq!(profiles[0].name, "A", "A (pri=2, no deps) must be first");

    // B depends on A → B must appear after A
    let pos_a = profiles.iter().position(|p| p.name == "A").unwrap();
    let pos_b = profiles.iter().position(|p| p.name == "B").unwrap();
    assert!(pos_a < pos_b, "B depends on A: A (pos {pos_a}) must precede B (pos {pos_b})");

    // D depends on B → D must appear after B
    let pos_d = profiles.iter().position(|p| p.name == "D").unwrap();
    assert!(pos_b < pos_d, "D depends on B: B (pos {pos_b}) must precede D (pos {pos_d})");

    // E depends on A → E must appear after A
    let pos_e = profiles.iter().position(|p| p.name == "E").unwrap();
    assert!(pos_a < pos_e, "E depends on A: A (pos {pos_a}) must precede E (pos {pos_e})");

    // F must be last — lowest priority, no dependencies
    assert_eq!(profiles[5].name, "F", "F (pri=0, no deps) must be last");
}

// ============================================================================
// test_sort_after_service_with_local_uuid — Dependencies on local_uuid
// ============================================================================

/// Verify that `btd_profile_sort_list` resolves `after_services` against
/// both `remote_uuid` and `local_uuid` fields (case-insensitive).
#[test]
fn test_sort_after_service_with_local_uuid() {
    // Profile X has local_uuid "svc-x" but no remote_uuid
    let x = make_profile_full("X", BTD_PROFILE_PRIORITY_HIGH, Some("svc-x"), None, vec![]);
    // Profile Y depends on "SVC-X" (uppercase) — should resolve against X's local_uuid
    let y = make_profile_full("Y", BTD_PROFILE_PRIORITY_HIGH, None, Some("svc-y"), vec!["SVC-X"]);

    let mut profiles = vec![y.clone(), x.clone()];

    btd_profile_sort_list(&mut profiles);
    check_sort_properties(&profiles, 2);

    // X must appear before Y because Y depends on X's local_uuid
    assert_eq!(profiles[0].name, "X", "X must come first (Y depends on SVC-X)");
    assert_eq!(profiles[1].name, "Y", "Y must come second (after X)");
}

// ============================================================================
// test_sort_cycle — Chain dependency with termination guarantee
// ============================================================================

/// Ported from "Sort Cycle" in `unit/test-profile.c` (lines 55–72).
///
/// Six profiles form a dependency chain: A ← B ← C ← D ← E ← F, with F
/// also depending on B. The C version uses a `cycle_break` parameter to handle
/// this; the Rust `btd_profile_sort_list` relies on `max_iterations = len²`
/// to terminate if cycles prevent convergence.
///
/// All profiles share the same priority (HIGH=2), so ordering is governed
/// entirely by `after_services` dependency resolution.
#[test]
fn test_sort_cycle() {
    let a = make_profile("A", BTD_PROFILE_PRIORITY_HIGH, Some("A"), vec![]);
    let b = make_profile("B", BTD_PROFILE_PRIORITY_HIGH, Some("B"), vec!["A"]);
    let c = make_profile("C", BTD_PROFILE_PRIORITY_HIGH, Some("C"), vec!["B"]);
    let d = make_profile("D", BTD_PROFILE_PRIORITY_HIGH, Some("D"), vec!["C"]);
    let e = make_profile("E", BTD_PROFILE_PRIORITY_HIGH, Some("E"), vec!["D"]);
    let f = make_profile("F", BTD_PROFILE_PRIORITY_HIGH, Some("F"), vec!["E", "B"]);

    let mut profiles = vec![a.clone(), b.clone(), c.clone(), d.clone(), e.clone(), f.clone()];

    // Must not panic — the topological pass terminates via max_iterations
    btd_profile_sort_list(&mut profiles);

    // A has no dependencies and must be first
    assert_eq!(profiles[0].name, "A", "A (no deps) must be first");
    assert_eq!(profiles.len(), 6, "all profiles must be present");

    // Verify chain ordering: A before B before C before D before E
    let pos_a = profiles.iter().position(|p| p.name == "A").unwrap();
    let pos_b = profiles.iter().position(|p| p.name == "B").unwrap();
    let pos_c = profiles.iter().position(|p| p.name == "C").unwrap();
    let pos_d = profiles.iter().position(|p| p.name == "D").unwrap();
    let pos_e = profiles.iter().position(|p| p.name == "E").unwrap();
    let pos_f = profiles.iter().position(|p| p.name == "F").unwrap();

    assert!(pos_a < pos_b, "A must precede B");
    assert!(pos_b < pos_c, "B must precede C");
    assert!(pos_c < pos_d, "C must precede D");
    assert!(pos_d < pos_e, "D must precede E");
    // F depends on both E and B — it must come after both
    assert!(pos_e < pos_f, "E must precede F");
    assert!(pos_b < pos_f, "B must precede F");
}

// ============================================================================
// test_sort_true_cycle — Mutual dependency cycle termination
// ============================================================================

/// Test that a genuine circular dependency (A depends on B, B depends on A)
/// does not cause an infinite loop or panic. The `max_iterations = len²`
/// guard in `btd_profile_sort_list` ensures termination.
#[test]
fn test_sort_true_cycle() {
    let a = make_profile("A", BTD_PROFILE_PRIORITY_HIGH, Some("A"), vec!["B"]);
    let b = make_profile("B", BTD_PROFILE_PRIORITY_HIGH, Some("B"), vec!["A"]);

    let mut profiles = vec![a.clone(), b.clone()];

    // Must terminate without panic
    btd_profile_sort_list(&mut profiles);

    // Both profiles must still be present
    assert_eq!(profiles.len(), 2, "both profiles must survive cycle handling");

    // No additional ordering guarantees for a true cycle — the algorithm
    // terminates after max_iterations and accepts whatever state it reached.
    let names: Vec<&str> = profiles.iter().map(|p| p.name.as_str()).collect();
    assert!(
        names.contains(&"A") && names.contains(&"B"),
        "both A and B must be present after cycle resolution"
    );
}

// ============================================================================
// test_sort_three_way_cycle — Three-node circular dependency
// ============================================================================

/// Verify termination for a three-node cycle: A→B→C→A.
#[test]
fn test_sort_three_way_cycle() {
    let a = make_profile("A", BTD_PROFILE_PRIORITY_HIGH, Some("A"), vec!["C"]);
    let b = make_profile("B", BTD_PROFILE_PRIORITY_HIGH, Some("B"), vec!["A"]);
    let c = make_profile("C", BTD_PROFILE_PRIORITY_HIGH, Some("C"), vec!["B"]);

    let mut profiles = vec![a.clone(), b.clone(), c.clone()];

    // Must terminate without panic
    btd_profile_sort_list(&mut profiles);

    assert_eq!(profiles.len(), 3, "all profiles must be present");
    let names: Vec<&str> = profiles.iter().map(|p| p.name.as_str()).collect();
    assert!(names.contains(&"A"));
    assert!(names.contains(&"B"));
    assert!(names.contains(&"C"));
}

// ============================================================================
// test_sort_fuzz — Randomised shuffle-and-sort verification
// ============================================================================

/// Ported from "Sort Fuzz" in `unit/test-profile.c` (lines 140–198).
///
/// Creates 50 profiles with graduated priorities and random `after_services`
/// dependencies (1–5 deps drawn from earlier profiles). Each iteration:
/// 1. Builds fresh profiles with random dependency graphs.
/// 2. Shuffles the profile order using a `Queue`-based Fisher-Yates variant.
/// 3. Sorts via `btd_profile_sort_list`.
/// 4. Verifies all sort invariants via `check_sort_properties`.
///
/// Repeated for 100 iterations (matching the C `shuffle_count = 100`).
#[test]
fn test_sort_fuzz() {
    let count: usize = 50;
    let shuffle_count: usize = 100;
    let mut rng = rand::thread_rng();

    for iteration in 0..shuffle_count {
        // Build profiles with graduated priorities: 3, 3, …, 2, 2, …, 1, 1, …
        // Formula from C: priority = 3 - 3 * j / count
        let mut uuids: Vec<String> = Vec::with_capacity(count);
        let mut profiles: Vec<Arc<BtdProfile>> = Vec::with_capacity(count);

        for j in 0..count {
            let priority = 3i32 - (3 * j / count) as i32;
            let uuid = format!("uuid-{j}");
            let name = format!("fuzz-{j}");

            let mut p = BtdProfile::new(&name);
            p.priority = priority;
            p.remote_uuid = Some(uuid.clone());

            // Profiles after the first one get 1..=min(5, j) random dependencies
            // drawn from earlier profiles' UUIDs (matching C lines 164–177).
            if j > 0 {
                let max_deps = std::cmp::min(5, j);
                let after_count = rng.gen_range(1..=max_deps);
                let mut after = Vec::with_capacity(after_count);
                for _ in 0..after_count {
                    let dep_idx = rng.gen_range(0..j);
                    after.push(uuids[dep_idx].clone());
                }
                p.after_services = after;
            }

            uuids.push(uuid);
            profiles.push(Arc::new(p));
        }

        // Shuffle using Queue-based index shuffle (exercises Queue API)
        let order = shuffle_indices(count, &mut rng);
        let mut shuffled: Vec<Arc<BtdProfile>> =
            order.iter().map(|&i| Arc::clone(&profiles[i])).collect();

        // Sort
        btd_profile_sort_list(&mut shuffled);

        // Verify all invariants
        check_sort_properties(&shuffled, count);

        // Verify no profiles were lost
        let mut found_count = 0;
        for original in &profiles {
            let found = shuffled.iter().any(|s| Arc::ptr_eq(s, original));
            assert!(found, "iteration {iteration}: profile '{}' lost during sort", original.name);
            found_count += 1;
        }
        assert_eq!(found_count, count);
    }
}

// ============================================================================
// test_profile_uuid_callback — BtdProfileUuidCb creation and invocation
// ============================================================================

/// Verify that `BtdProfileUuidCb` correctly stores a UUID string and an
/// associated callback, and that the callback can be invoked with a profile
/// reference.
///
/// This tests the UUID matching mechanism used by `btd_profile_find_remote_uuid`
/// to iterate registered profiles and invoke callbacks for UUID matches.
#[test]
fn test_profile_uuid_callback() {
    let target_uuid = "00001101-0000-1000-8000-00805f9b34fb";
    let profile = make_profile("SPP", BTD_PROFILE_PRIORITY_MEDIUM, Some(target_uuid), vec![]);

    let called = Arc::new(AtomicBool::new(false));
    let called_clone = Arc::clone(&called);

    let received_name = Arc::new(std::sync::Mutex::new(String::new()));
    let received_name_clone = Arc::clone(&received_name);

    let uuid_cb = BtdProfileUuidCb {
        uuid: target_uuid.to_owned(),
        callback: Box::new(move |p: &Arc<BtdProfile>| {
            called_clone.store(true, Ordering::SeqCst);
            *received_name_clone.lock().unwrap() = p.name.clone();
        }),
    };

    // Verify UUID field matches the profile's remote_uuid
    assert_eq!(
        uuid_cb.uuid,
        profile.remote_uuid.as_ref().unwrap().as_str(),
        "UUID callback UUID must match profile remote_uuid"
    );

    // Invoke the callback with the profile
    (uuid_cb.callback)(&profile);

    // Verify callback was invoked
    assert!(called.load(Ordering::SeqCst), "callback must have been invoked");

    // Verify callback received the correct profile
    let name = received_name.lock().unwrap();
    assert_eq!(name.as_str(), "SPP", "callback must receive the correct profile");
}

// ============================================================================
// test_profile_uuid_callback_multiple — Multiple UUID callbacks
// ============================================================================

/// Verify that multiple `BtdProfileUuidCb` instances with different UUIDs
/// can coexist and be selectively invoked.
#[test]
fn test_profile_uuid_callback_multiple() {
    let counter = Arc::new(AtomicUsize::new(0));

    let uuid_a = "0000110a-0000-1000-8000-00805f9b34fb";
    let uuid_b = "0000110b-0000-1000-8000-00805f9b34fb";

    let counter_a = Arc::clone(&counter);
    let cb_a = BtdProfileUuidCb {
        uuid: uuid_a.to_owned(),
        callback: Box::new(move |_p: &Arc<BtdProfile>| {
            counter_a.fetch_add(1, Ordering::SeqCst);
        }),
    };

    let counter_b = Arc::clone(&counter);
    let cb_b = BtdProfileUuidCb {
        uuid: uuid_b.to_owned(),
        callback: Box::new(move |_p: &Arc<BtdProfile>| {
            counter_b.fetch_add(10, Ordering::SeqCst);
        }),
    };

    let profile_a = make_profile("ProfileA", BTD_PROFILE_PRIORITY_LOW, Some(uuid_a), vec![]);
    let profile_b = make_profile("ProfileB", BTD_PROFILE_PRIORITY_LOW, Some(uuid_b), vec![]);

    // Simulate UUID matching: invoke only the callback whose UUID matches
    let callbacks = [&cb_a, &cb_b];
    for cb in &callbacks {
        if cb.uuid == uuid_a {
            (cb.callback)(&profile_a);
        }
        if cb.uuid == uuid_b {
            (cb.callback)(&profile_b);
        }
    }

    // cb_a invoked once (+1), cb_b invoked once (+10)
    assert_eq!(counter.load(Ordering::SeqCst), 11, "both callbacks must be invoked exactly once");
}

// ============================================================================
// test_profile_multiple_configurations — Various profile field combinations
// ============================================================================

/// Verify that profiles can be created with a range of field combinations
/// and that `btd_profile_sort_list` handles them all correctly.
#[test]
fn test_profile_multiple_configurations() {
    // Profile with all fields set
    let full = {
        let mut p = BtdProfile::new("FullProfile");
        p.priority = BTD_PROFILE_PRIORITY_HIGH;
        p.bearer = 2; // BREDR
        p.local_uuid = Some("0000110a-0000-1000-8000-00805f9b34fb".to_owned());
        p.remote_uuid = Some("0000110b-0000-1000-8000-00805f9b34fb".to_owned());
        p.auto_connect = true;
        p.external = false;
        p.experimental = true;
        p.testing = true;
        p.after_services = vec![];
        Arc::new(p)
    };

    // Profile with minimal fields (just name)
    let minimal = Arc::new(BtdProfile::new("MinimalProfile"));

    // Profile with only remote UUID
    let remote_only = make_profile(
        "RemoteOnly",
        BTD_PROFILE_PRIORITY_LOW,
        Some("0000110c-0000-1000-8000-00805f9b34fb"),
        vec![],
    );

    // Profile with dependencies
    let dependent = make_profile(
        "Dependent",
        BTD_PROFILE_PRIORITY_MEDIUM,
        Some("0000110d-0000-1000-8000-00805f9b34fb"),
        vec!["0000110b-0000-1000-8000-00805f9b34fb"],
    );

    let mut profiles = vec![dependent.clone(), minimal.clone(), remote_only.clone(), full.clone()];

    btd_profile_sort_list(&mut profiles);
    check_sort_properties(&profiles, 4);

    // Full profile (HIGH priority) must precede Minimal (MEDIUM, default)
    let pos_full = profiles.iter().position(|p| p.name == "FullProfile").unwrap();
    let pos_minimal = profiles.iter().position(|p| p.name == "MinimalProfile").unwrap();
    assert!(pos_full < pos_minimal, "FullProfile (HIGH) must precede MinimalProfile (MEDIUM)");

    // Dependent has after_services referencing FullProfile's remote_uuid
    let pos_dependent = profiles.iter().position(|p| p.name == "Dependent").unwrap();
    assert!(
        pos_full < pos_dependent,
        "FullProfile must precede Dependent (after_services constraint)"
    );

    // RemoteOnly (LOW) must come after profiles with higher priority and no deps
    let pos_remote = profiles.iter().position(|p| p.name == "RemoteOnly").unwrap();
    assert!(
        pos_minimal < pos_remote || !profiles[pos_remote].after_services.is_empty(),
        "RemoteOnly (LOW) must not precede MinimalProfile (MEDIUM) without deps"
    );
}

// ============================================================================
// test_sort_all_same_priority — Stable sort with identical priorities
// ============================================================================

/// Verify that when all profiles share the same priority and have no
/// `after_services`, the stable sort preserves the original insertion order.
#[test]
fn test_sort_all_same_priority() {
    let profiles_data = ["Alpha", "Beta", "Gamma", "Delta", "Epsilon"];
    let originals: Vec<Arc<BtdProfile>> = profiles_data
        .iter()
        .map(|name| make_profile(name, BTD_PROFILE_PRIORITY_MEDIUM, None, vec![]))
        .collect();

    let mut sorted = originals.clone();
    btd_profile_sort_list(&mut sorted);

    check_sort_properties(&sorted, 5);

    // Stable sort must preserve original order for equal-priority profiles
    for (i, p) in sorted.iter().enumerate() {
        assert_eq!(
            p.name, profiles_data[i],
            "position {i}: expected '{}', got '{}'",
            profiles_data[i], p.name
        );
    }
}

// ============================================================================
// test_sort_reverse_priority — Already reverse-sorted input
// ============================================================================

/// Verify that a list sorted in ascending priority (wrong order) is correctly
/// re-sorted into descending priority order.
#[test]
fn test_sort_reverse_priority() {
    let low = make_profile("Low", BTD_PROFILE_PRIORITY_LOW, None, vec![]);
    let med = make_profile("Med", BTD_PROFILE_PRIORITY_MEDIUM, None, vec![]);
    let high = make_profile("High", BTD_PROFILE_PRIORITY_HIGH, None, vec![]);

    // Input in ascending order (opposite of desired)
    let mut profiles = vec![low.clone(), med.clone(), high.clone()];

    btd_profile_sort_list(&mut profiles);
    check_sort_properties(&profiles, 3);

    assert_eq!(profiles[0].name, "High");
    assert_eq!(profiles[1].name, "Med");
    assert_eq!(profiles[2].name, "Low");
}

// ============================================================================
// test_sort_mixed_deps_and_no_deps — Mix of dependent and independent profiles
// ============================================================================

/// Verify correct interleaving when some profiles have `after_services` and
/// others do not, across different priority levels.
#[test]
fn test_sort_mixed_deps_and_no_deps() {
    // Independent HIGH priority
    let ind_high = make_profile("IndHigh", BTD_PROFILE_PRIORITY_HIGH, Some("IH"), vec![]);
    // Dependent HIGH priority (depends on IndHigh)
    let dep_high = make_profile("DepHigh", BTD_PROFILE_PRIORITY_HIGH, Some("DH"), vec!["IH"]);
    // Independent MEDIUM priority
    let ind_med = make_profile("IndMed", BTD_PROFILE_PRIORITY_MEDIUM, Some("IM"), vec![]);
    // Dependent LOW priority (depends on IndMed)
    let dep_low = make_profile("DepLow", BTD_PROFILE_PRIORITY_LOW, Some("DL"), vec!["IM"]);

    let mut profiles = vec![dep_low.clone(), dep_high.clone(), ind_med.clone(), ind_high.clone()];

    btd_profile_sort_list(&mut profiles);
    check_sort_properties(&profiles, 4);

    // IndHigh must precede DepHigh (dependency)
    let pos_ih = profiles.iter().position(|p| p.name == "IndHigh").unwrap();
    let pos_dh = profiles.iter().position(|p| p.name == "DepHigh").unwrap();
    assert!(pos_ih < pos_dh, "IndHigh must precede DepHigh");

    // IndMed must precede DepLow (dependency)
    let pos_im = profiles.iter().position(|p| p.name == "IndMed").unwrap();
    let pos_dl = profiles.iter().position(|p| p.name == "DepLow").unwrap();
    assert!(pos_im < pos_dl, "IndMed must precede DepLow");
}
