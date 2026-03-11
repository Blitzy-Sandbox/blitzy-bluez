// SPDX-License-Identifier: GPL-2.0-or-later
//
// tests/unit/test_queue.rs — Rust port of unit/test-queue.c
//
// Comprehensive unit tests for `bluez_shared::util::queue::Queue<T>`,
// verifying all queue operations: push_tail, push_head, push_after,
// pop_head, peek_head, peek_tail, foreach, remove, remove_all, len,
// and is_empty.  Every test function maps to an identically-named
// test in the original C file (`unit/test-queue.c`).

use bluez_shared::util::queue::Queue;

// ============================================================================
// test_basic — Stress test: 1024 iterations of push / pop / verify
// ============================================================================

/// Stress test — 1024 iterations of n+1 items pushed and popped.
///
/// Ported from `test_basic` in `unit/test-queue.c` (lines 21–48).
/// For each iteration n ∈ [0, 1024):
///   1. Creates a new queue.
///   2. Pushes values 0..=n via `push_tail`.
///   3. Verifies `len() == n + 1` and `!is_empty()`.
///   4. Pops all items and verifies strict FIFO order.
///   5. Asserts the queue is empty (`is_empty() == true`, `len() == 0`).
///
/// The C original used `UINT_TO_PTR(i)` / `PTR_TO_UINT(ptr)` to store
/// integer values as `void *`.  In Rust, `usize` values are stored
/// directly with no pointer casting required.
#[test]
fn test_basic() {
    for n in 0..1024usize {
        let mut queue = Queue::new();

        // Push n+1 values: 0, 1, 2, …, n
        for i in 0..=n {
            queue.push_tail(i);
        }

        assert_eq!(queue.len(), n + 1);
        assert!(!queue.is_empty());

        // Pop each value and verify FIFO ordering
        for i in 0..=n {
            let val = queue.pop_head();
            assert_eq!(val, Some(i), "iteration {n}: pop {i} mismatch");
        }

        assert!(queue.is_empty());
        assert_eq!(queue.len(), 0);
        // Queue is dropped via RAII — equivalent of queue_destroy(q, NULL)
    }
}

// ============================================================================
// test_foreach_destroy — Foreach + drop safety
// ============================================================================

/// Verify foreach visits all elements, followed by RAII cleanup.
///
/// Ported from `test_foreach_destroy` in `unit/test-queue.c` (lines 57–69).
/// The C original tested that destroying the queue from within a foreach
/// callback is safe (the C queue implementation must tolerate this).
/// Rust's ownership model prevents destroy-during-iterate at compile time.
/// This test verifies:
///   1. `foreach` correctly visits every element in FIFO order.
///   2. The queue is safely dropped after iteration completes.
#[test]
fn test_foreach_destroy() {
    let mut queue = Queue::new();
    queue.push_tail(1usize);
    queue.push_tail(2usize);

    // Collect all elements visited by foreach
    let mut visited = Vec::new();
    queue.foreach(|item| {
        visited.push(*item);
    });

    assert_eq!(visited, vec![1, 2]);

    // Queue dropped here via RAII — Rust equivalent of queue_destroy(queue, NULL)
    drop(queue);
}

// ============================================================================
// test_foreach_remove — Foreach + individual removal
// ============================================================================

/// Foreach followed by removal of each visited element.
///
/// Ported from `test_foreach_remove` in `unit/test-queue.c` (lines 78–91).
/// The C original removed each element from within the foreach callback
/// (`queue_remove(queue, data)` inside `foreach_remove_cb`).  Rust's borrow
/// checker prevents mutation during `&self` iteration.  This test verifies
/// the idiomatic Rust equivalent:
///   1. Iterate with `foreach`, collecting each element.
///   2. After iteration completes, remove each collected element.
///   3. Assert the queue is empty.
#[test]
fn test_foreach_remove() {
    let mut queue = Queue::new();
    queue.push_tail(1usize);
    queue.push_tail(2usize);

    // Phase 1: collect elements during foreach
    let mut visited = Vec::new();
    queue.foreach(|item| {
        visited.push(*item);
    });
    assert_eq!(visited, vec![1, 2]);

    // Phase 2: remove each visited item
    for item in &visited {
        assert!(queue.remove(item));
    }
    assert!(queue.is_empty());
}

// ============================================================================
// test_foreach_remove_all — Foreach + bulk removal
// ============================================================================

/// Foreach followed by remove_all to clear the entire queue.
///
/// Ported from `test_foreach_remove_all` in `unit/test-queue.c` (lines 100–113).
/// The C original called `queue_remove_all(queue, NULL, NULL, NULL)` from
/// within the foreach callback, clearing the queue during iteration.  Rust's
/// ownership model prevents this.  This test verifies:
///   1. `foreach` visits all elements correctly.
///   2. `remove_all(None)` clears the queue and returns the correct count.
#[test]
fn test_foreach_remove_all() {
    let mut queue = Queue::new();
    queue.push_tail(1usize);
    queue.push_tail(2usize);

    // Verify foreach visits both elements
    let mut visited = Vec::new();
    queue.foreach(|item| {
        visited.push(*item);
    });
    assert_eq!(visited, vec![1, 2]);

    // remove_all(None) clears the entire queue
    let removed = queue.remove_all(None::<fn(&usize) -> bool>);
    assert_eq!(removed, 2);
    assert!(queue.is_empty());
}

// ============================================================================
// test_foreach_remove_backward — Foreach + reverse-order removal
// ============================================================================

/// Foreach followed by backward (reverse-order) removal of elements.
///
/// Ported from `test_foreach_remove_backward` in `unit/test-queue.c`
/// (lines 123–136).  The C original removed elements in reverse order
/// during foreach (removing the second item before the first).  This test
/// verifies that the Rust queue correctly handles removal regardless of
/// order:
///   1. `foreach` visits [1, 2] in FIFO order.
///   2. Remove 2 first, then 1 — reverse of insertion order.
///   3. Assert the queue is empty.
#[test]
fn test_foreach_remove_backward() {
    let mut queue = Queue::new();
    queue.push_tail(1usize);
    queue.push_tail(2usize);

    // Collect elements in FIFO order
    let mut visited = Vec::new();
    queue.foreach(|item| {
        visited.push(*item);
    });
    assert_eq!(visited, vec![1, 2]);

    // Remove in reverse (backward) order
    for item in visited.iter().rev() {
        assert!(queue.remove(item));
    }
    assert!(queue.is_empty());
}

// ============================================================================
// test_destroy_remove — Remove during destruction
// ============================================================================

/// Safe cleanup after batch removal via remove_all + drop.
///
/// Ported from `test_destroy_remove` in `unit/test-queue.c` (lines 145–156).
/// The C original used a static queue and a destroy callback that called
/// `queue_remove(static_queue, data)` for each element during
/// `queue_destroy(static_queue, destroy_remove)`.  This tested that
/// remove-during-destroy is safe.
///
/// In Rust, RAII handles cleanup.  This test verifies the equivalent:
///   1. `remove_all(None)` removes all elements (batch removal).
///   2. The queue is safely dropped after all elements are gone.
#[test]
fn test_destroy_remove() {
    let mut queue = Queue::new();
    queue.push_tail(1usize);
    queue.push_tail(2usize);

    // Remove all elements — Rust equivalent of destroy-with-remove-callback
    let removed = queue.remove_all(None::<fn(&usize) -> bool>);
    assert_eq!(removed, 2);
    assert!(queue.is_empty());

    // Safe drop after all elements removed
    drop(queue);
}

// ============================================================================
// test_push_after — Ordered insertion after a reference element
// ============================================================================

/// Comprehensive test of push_after: insert after a given reference element.
///
/// Ported from `test_push_after` in `unit/test-queue.c` (lines 158–209).
/// Tests:
///   1. Building an ordered sequence [0..=6] from a sparse starting state
///      via push_after.
///   2. Invalid insertion returns `false` when the reference element is absent.
///   3. peek_head / peek_tail correctness after insertions.
///   4. Complete FIFO pop verification of the final sequence.
///   5. Duplicate-element handling: push_after inserts after the *first*
///      matching element (C pointer identity maps to Rust PartialEq match).
#[test]
fn test_push_after() {
    // ------------------------------------------------------------------
    // Phase 1: Build ordered sequence via push_after
    // ------------------------------------------------------------------
    let mut queue = Queue::new();

    // Pre-populate with sparse values: [0, 2, 5]
    queue.push_tail(0usize);
    queue.push_tail(2usize);
    queue.push_tail(5usize);
    assert_eq!(queue.len(), 3);

    // Invalid insertion — 6 is not in the queue, should return false
    assert!(!queue.push_after(&6, 1));
    assert_eq!(queue.len(), 3);

    // Insert 1 after 0: [0, 1, 2, 5]
    assert!(queue.push_after(&0, 1));
    // Insert 3 after 2: [0, 1, 2, 3, 5]
    assert!(queue.push_after(&2, 3));
    // Insert 4 after 3: [0, 1, 2, 3, 4, 5]
    assert!(queue.push_after(&3, 4));
    // Insert 6 after 5: [0, 1, 2, 3, 4, 5, 6]
    assert!(queue.push_after(&5, 6));

    // Verify head, tail, and length
    assert_eq!(queue.peek_head(), Some(&0));
    assert_eq!(queue.peek_tail(), Some(&6));
    assert_eq!(queue.len(), 7);

    // Pop all and verify ascending order 0..=6
    for expected in 0..=6usize {
        assert_eq!(queue.pop_head(), Some(expected), "push_after sequence: expected {expected}");
    }
    assert!(queue.is_empty());

    // ------------------------------------------------------------------
    // Phase 2: Duplicate-element handling
    // ------------------------------------------------------------------
    // C test: push_head three 1s → [1, 1, 1]
    // Then push_after(queue, UINT_TO_PTR(1), UINT_TO_PTR(0))
    // inserts 0 after the first 1 → [1, 0, 1, 1]
    let mut queue2 = Queue::new();
    queue2.push_head(1usize);
    queue2.push_head(1usize);
    queue2.push_head(1usize);

    // Insert 0 after the first occurrence of 1
    assert!(queue2.push_after(&1, 0));
    assert_eq!(queue2.len(), 4);

    // Expected pop order: 1, 0, 1, 1
    assert_eq!(queue2.pop_head(), Some(1));
    assert_eq!(queue2.pop_head(), Some(0));
    assert_eq!(queue2.pop_head(), Some(1));
    assert_eq!(queue2.pop_head(), Some(1));
    assert!(queue2.is_empty());
}

// ============================================================================
// test_remove_all — Predicate-based bulk removal
// ============================================================================

/// Tests remove_all with match predicates.
///
/// Ported from `test_remove_all` in `unit/test-queue.c` (lines 225–247).
/// The C original tested three cases:
///   1. Push 10, `remove_all(match_int, 10)` → removes 1 item.
///   2. Push NULL, `remove_all(match_ptr, NULL)` → removes 1 item.
///   3. Push UINT_TO_PTR(0), `remove_all(match_int, 0)` → removes 1 item.
///
/// Cases 2 and 3 distinguished between pointer-identity (`match_ptr`) and
/// value-equality (`match_int`) for NULL/0 in C.  In Rust, `0usize` is a
/// normal value — both reduce to value equality.  We preserve all three
/// cases for behavioral parity.
#[test]
fn test_remove_all_match() {
    let mut queue = Queue::new();

    // Case 1: Push 10, remove_all matching value == 10
    queue.push_tail(10usize);
    let count = queue.remove_all(Some(|item: &usize| *item == 10));
    assert_eq!(count, 1);
    assert!(queue.is_empty());

    // Case 2: Push 0 (Rust equivalent of C NULL), remove_all matching == 0
    queue.push_tail(0usize);
    let count = queue.remove_all(Some(|item: &usize| *item == 0));
    assert_eq!(count, 1);
    assert!(queue.is_empty());

    // Case 3: Push 0 (C UINT_TO_PTR(0) equivalent), remove_all matching == 0
    queue.push_tail(0usize);
    let count = queue.remove_all(Some(|item: &usize| *item == 0));
    assert_eq!(count, 1);
    assert!(queue.is_empty());
}
