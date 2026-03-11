// SPDX-License-Identifier: LGPL-2.1-or-later
//
// BlueZ - Bluetooth protocol stack for Linux
//
// Copyright (C) 2012-2014  Intel Corporation. All rights reserved.
//
// Rust rewrite of src/shared/queue.c / src/shared/queue.h

//! Generic queue data structure wrapping [`VecDeque<T>`].
//!
//! This module provides [`Queue<T>`], a type-safe generic replacement for the C
//! `struct queue` (an opaque, reference-counted, singly-linked list with `void*`
//! data pointers). The Rust version uses [`std::collections::VecDeque<T>`] as
//! the backing store, providing:
//!
//! - O(1) amortized `push_tail`/`push_head`/`pop_head` (matching the C version)
//! - Better cache locality than a linked list
//! - Full type safety via generics (replacing `void*` casts)
//! - Ownership semantics (replacing manual `ref_count` / `queue_ref` / `queue_unref`)
//! - Closure-based iteration (replacing `callback + void* user_data`)
//!
//! # Migration from C
//!
//! | C API | Rust API |
//! |-------|---------|
//! | `queue_new()` | `Queue::new()` |
//! | `queue_destroy(q, free)` | `drop(q)` (automatic) |
//! | `queue_ref` / `queue_unref` | `Arc<Mutex<Queue<T>>>` if shared |
//! | `queue_push_tail(q, data)` | `q.push_tail(data)` |
//! | `queue_push_head(q, data)` | `q.push_head(data)` |
//! | `queue_push_after(q, entry, data)` | `q.push_after(&entry, data)` |
//! | `queue_pop_head(q)` | `q.pop_head()` |
//! | `queue_peek_head(q)` | `q.peek_head()` |
//! | `queue_peek_tail(q)` | `q.peek_tail()` |
//! | `queue_foreach(q, cb, ud)` | `q.foreach(\|item\| { ... })` |
//! | `queue_find(q, cb, ud)` | `q.find(\|item\| { ... })` |
//! | `queue_remove(q, data)` | `q.remove(&data)` |
//! | `queue_remove_if(q, cb, ud)` | `q.remove_if(\|item\| { ... })` |
//! | `queue_remove_all(q, cb, ud, destroy)` | `q.remove_all(predicate)` |
//! | `queue_length(q)` | `q.len()` |
//! | `queue_isempty(q)` | `q.is_empty()` |
//! | `queue_get_entries(q)` | `q.as_slice()` / `q.iter()` |

use std::collections::VecDeque;

// =============================================================================
// Queue<T> — Core type definition
// =============================================================================

/// A generic queue wrapping [`VecDeque<T>`].
///
/// Replaces the C `struct queue` (opaque, ref-counted, singly-linked list with
/// `void*` data). Elements are stored contiguously for cache-friendly access.
///
/// # Ownership
///
/// The queue owns all its elements. When the queue is dropped, all contained
/// elements are dropped automatically. If shared ownership is needed, callers
/// should wrap the queue in `Arc<Mutex<Queue<T>>>`.
///
/// # Examples
///
/// ```
/// use bluez_shared::util::queue::Queue;
///
/// let mut q = Queue::new();
/// q.push_tail(1);
/// q.push_tail(2);
/// q.push_tail(3);
///
/// assert_eq!(q.peek_head(), Some(&1));
/// assert_eq!(q.pop_head(), Some(1));
/// assert_eq!(q.len(), 2);
/// ```
pub struct Queue<T> {
    inner: VecDeque<T>,
}

// =============================================================================
// Constructor and Default
// =============================================================================

impl<T> Queue<T> {
    /// Creates a new, empty queue.
    ///
    /// Replaces C `queue_new()` (queue.c lines 43-53). No reference counting
    /// is needed — Rust ownership handles lifetime automatically.
    ///
    /// # Examples
    ///
    /// ```
    /// use bluez_shared::util::queue::Queue;
    /// let q: Queue<i32> = Queue::new();
    /// assert!(q.is_empty());
    /// ```
    #[inline]
    pub fn new() -> Self {
        Queue { inner: VecDeque::new() }
    }

    // =========================================================================
    // Push operations
    // =========================================================================

    /// Appends an element to the back of the queue.
    ///
    /// Replaces C `queue_push_tail()` (queue.c lines 75-95). Always returns
    /// `true` since Rust's `VecDeque` allocation only panics on OOM (which
    /// aborts the process), matching the C behavior where `new0()` also aborts
    /// on allocation failure.
    ///
    /// # Examples
    ///
    /// ```
    /// use bluez_shared::util::queue::Queue;
    /// let mut q = Queue::new();
    /// assert!(q.push_tail(42));
    /// assert_eq!(q.peek_tail(), Some(&42));
    /// ```
    #[inline]
    pub fn push_tail(&mut self, data: T) -> bool {
        self.inner.push_back(data);
        true
    }

    /// Prepends an element to the front of the queue.
    ///
    /// Replaces C `queue_push_head()` (queue.c lines 97-116). Always returns
    /// `true`.
    ///
    /// # Examples
    ///
    /// ```
    /// use bluez_shared::util::queue::Queue;
    /// let mut q = Queue::new();
    /// q.push_tail(2);
    /// q.push_head(1);
    /// assert_eq!(q.peek_head(), Some(&1));
    /// ```
    #[inline]
    pub fn push_head(&mut self, data: T) -> bool {
        self.inner.push_front(data);
        true
    }

    /// Inserts an element immediately after a matching entry.
    ///
    /// Replaces C `queue_push_after()` (queue.c lines 118-148). The C version
    /// compares raw data pointers (`tmp->data == entry`); the Rust version uses
    /// [`PartialEq`] for value-based comparison.
    ///
    /// Returns `false` if `entry` is not found in the queue.
    ///
    /// # Examples
    ///
    /// ```
    /// use bluez_shared::util::queue::Queue;
    /// let mut q = Queue::new();
    /// q.push_tail(1);
    /// q.push_tail(3);
    /// assert!(q.push_after(&1, 2));
    /// // Queue is now: [1, 2, 3]
    /// assert_eq!(q.pop_head(), Some(1));
    /// assert_eq!(q.pop_head(), Some(2));
    /// assert_eq!(q.pop_head(), Some(3));
    /// ```
    pub fn push_after(&mut self, entry: &T, data: T) -> bool
    where
        T: PartialEq,
    {
        // Find the position of the entry we want to insert after
        let pos = self.inner.iter().position(|item| item == entry);
        match pos {
            Some(idx) => {
                // Insert after the found element (at index idx + 1)
                self.inner.insert(idx + 1, data);
                true
            }
            None => false,
        }
    }

    // =========================================================================
    // Pop / Peek operations
    // =========================================================================

    /// Removes and returns the element at the front of the queue.
    ///
    /// Replaces C `queue_pop_head()` (queue.c lines 150-172). Returns `None`
    /// if the queue is empty (C returns `NULL`).
    ///
    /// # Examples
    ///
    /// ```
    /// use bluez_shared::util::queue::Queue;
    /// let mut q = Queue::new();
    /// q.push_tail(1);
    /// q.push_tail(2);
    /// assert_eq!(q.pop_head(), Some(1));
    /// assert_eq!(q.pop_head(), Some(2));
    /// assert_eq!(q.pop_head(), None);
    /// ```
    #[inline]
    pub fn pop_head(&mut self) -> Option<T> {
        self.inner.pop_front()
    }

    /// Returns a reference to the element at the front without removing it.
    ///
    /// Replaces C `queue_peek_head()` (queue.c lines 174-180). Returns `None`
    /// if the queue is empty.
    ///
    /// # Examples
    ///
    /// ```
    /// use bluez_shared::util::queue::Queue;
    /// let mut q = Queue::new();
    /// assert_eq!(q.peek_head(), None);
    /// q.push_tail(42);
    /// assert_eq!(q.peek_head(), Some(&42));
    /// ```
    #[inline]
    pub fn peek_head(&self) -> Option<&T> {
        self.inner.front()
    }

    /// Returns a reference to the element at the back without removing it.
    ///
    /// Replaces C `queue_peek_tail()` (queue.c lines 182-188). Returns `None`
    /// if the queue is empty.
    ///
    /// # Examples
    ///
    /// ```
    /// use bluez_shared::util::queue::Queue;
    /// let mut q = Queue::new();
    /// q.push_tail(1);
    /// q.push_tail(2);
    /// assert_eq!(q.peek_tail(), Some(&2));
    /// ```
    #[inline]
    pub fn peek_tail(&self) -> Option<&T> {
        self.inner.back()
    }

    // =========================================================================
    // Iteration
    // =========================================================================

    /// Applies a function to each element by shared reference.
    ///
    /// Replaces C `queue_foreach()` (queue.c lines 190-211). The C version uses
    /// `queue_ref()`/`queue_unref()` to protect against queue modification
    /// during iteration; Rust's borrow checker provides this safety statically
    /// via the `&self` immutable borrow.
    ///
    /// # Examples
    ///
    /// ```
    /// use bluez_shared::util::queue::Queue;
    /// let mut q = Queue::new();
    /// q.push_tail(1);
    /// q.push_tail(2);
    /// let mut sum = 0;
    /// q.foreach(|item| sum += item);
    /// assert_eq!(sum, 3);
    /// ```
    #[inline]
    pub fn foreach(&self, func: impl FnMut(&T)) {
        self.inner.iter().for_each(func);
    }

    /// Applies a function to each element by mutable reference.
    ///
    /// This has no direct C equivalent (the C queue stores `void*` pointers and
    /// does not provide mutable iteration). Provided for Rust ergonomics.
    ///
    /// # Examples
    ///
    /// ```
    /// use bluez_shared::util::queue::Queue;
    /// let mut q = Queue::new();
    /// q.push_tail(1);
    /// q.push_tail(2);
    /// q.foreach_mut(|item| *item *= 10);
    /// assert_eq!(q.pop_head(), Some(10));
    /// assert_eq!(q.pop_head(), Some(20));
    /// ```
    #[inline]
    pub fn foreach_mut(&mut self, func: impl FnMut(&mut T)) {
        self.inner.iter_mut().for_each(func);
    }

    /// Returns an iterator yielding shared references to each element.
    ///
    /// Replaces iteration via `queue_get_entries()` + linked-list traversal.
    ///
    /// # Examples
    ///
    /// ```
    /// use bluez_shared::util::queue::Queue;
    /// let mut q = Queue::new();
    /// q.push_tail(1);
    /// q.push_tail(2);
    /// let v: Vec<&i32> = q.iter().collect();
    /// assert_eq!(v, vec![&1, &2]);
    /// ```
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.inner.iter()
    }

    /// Returns an iterator yielding mutable references to each element.
    ///
    /// # Examples
    ///
    /// ```
    /// use bluez_shared::util::queue::Queue;
    /// let mut q = Queue::new();
    /// q.push_tail(1);
    /// for item in q.iter_mut() {
    ///     *item += 10;
    /// }
    /// assert_eq!(q.peek_head(), Some(&11));
    /// ```
    #[inline]
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
        self.inner.iter_mut()
    }

    // =========================================================================
    // Find operations
    // =========================================================================

    /// Finds the first element matching a predicate.
    ///
    /// Replaces C `queue_find()` (queue.c lines 218-234) when called with a
    /// non-NULL match function. The predicate replaces the C
    /// `queue_match_func_t callback + void* match_data` pattern.
    ///
    /// # Examples
    ///
    /// ```
    /// use bluez_shared::util::queue::Queue;
    /// let mut q = Queue::new();
    /// q.push_tail(10);
    /// q.push_tail(20);
    /// q.push_tail(30);
    /// assert_eq!(q.find(|x| *x > 15), Some(&20));
    /// assert_eq!(q.find(|x| *x > 100), None);
    /// ```
    #[inline]
    pub fn find<F>(&self, predicate: F) -> Option<&T>
    where
        F: Fn(&T) -> bool,
    {
        self.inner.iter().find(|item| predicate(item))
    }

    /// Finds the first element equal to the target value.
    ///
    /// Replaces C `queue_find()` (queue.c lines 218-234) when called with a
    /// NULL match function (i.e., `direct_match` which compares raw pointers).
    /// In Rust, [`PartialEq`] provides value-based equality.
    ///
    /// # Examples
    ///
    /// ```
    /// use bluez_shared::util::queue::Queue;
    /// let mut q = Queue::new();
    /// q.push_tail("hello".to_string());
    /// q.push_tail("world".to_string());
    /// assert!(q.find_by_value(&"world".to_string()).is_some());
    /// assert!(q.find_by_value(&"missing".to_string()).is_none());
    /// ```
    #[inline]
    pub fn find_by_value(&self, target: &T) -> Option<&T>
    where
        T: PartialEq,
    {
        self.inner.iter().find(|item| *item == target)
    }

    // =========================================================================
    // Remove operations
    // =========================================================================

    /// Removes the first element equal to `data`.
    ///
    /// Replaces C `queue_remove()` (queue.c lines 236-263). The C version
    /// compares raw data pointers; the Rust version uses [`PartialEq`].
    ///
    /// Returns `true` if an element was found and removed, `false` otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// use bluez_shared::util::queue::Queue;
    /// let mut q = Queue::new();
    /// q.push_tail(1);
    /// q.push_tail(2);
    /// q.push_tail(3);
    /// assert!(q.remove(&2));
    /// assert!(!q.remove(&99));
    /// assert_eq!(q.len(), 2);
    /// ```
    pub fn remove(&mut self, data: &T) -> bool
    where
        T: PartialEq,
    {
        if let Some(pos) = self.inner.iter().position(|item| item == data) {
            self.inner.remove(pos);
            true
        } else {
            false
        }
    }

    /// Removes and returns the first element matching a predicate.
    ///
    /// Replaces C `queue_remove_if()` (queue.c lines 265-303). The predicate
    /// replaces the `queue_match_func_t callback + void* user_data` pattern.
    /// Returns `None` if no element matches.
    ///
    /// # Examples
    ///
    /// ```
    /// use bluez_shared::util::queue::Queue;
    /// let mut q = Queue::new();
    /// q.push_tail(1);
    /// q.push_tail(2);
    /// q.push_tail(3);
    /// assert_eq!(q.remove_if(|x| *x == 2), Some(2));
    /// assert_eq!(q.len(), 2);
    /// assert_eq!(q.remove_if(|x| *x == 99), None);
    /// ```
    pub fn remove_if<F>(&mut self, predicate: F) -> Option<T>
    where
        F: Fn(&T) -> bool,
    {
        let pos = self.inner.iter().position(predicate)?;
        self.inner.remove(pos)
    }

    /// Removes elements matching a predicate, or all elements if no predicate
    /// is given.
    ///
    /// Replaces C `queue_remove_all()` (queue.c lines 305-349):
    /// - When `predicate` is `None`: clears the entire queue and returns the
    ///   count of removed elements.
    /// - When `predicate` is `Some(f)`: removes all elements for which `f`
    ///   returns `true`, returning the count of removed elements.
    ///
    /// The C version accepts an optional `queue_destroy_func_t` to free each
    /// removed element; in Rust, the [`Drop`] trait handles cleanup
    /// automatically.
    ///
    /// # Examples
    ///
    /// ```
    /// use bluez_shared::util::queue::Queue;
    /// let mut q = Queue::new();
    /// q.push_tail(1);
    /// q.push_tail(2);
    /// q.push_tail(3);
    /// q.push_tail(4);
    ///
    /// // Remove all even numbers
    /// let removed = q.remove_all(Some(|x: &i32| *x % 2 == 0));
    /// assert_eq!(removed, 2);
    /// assert_eq!(q.len(), 2);
    ///
    /// // Remove everything
    /// let removed = q.remove_all(None::<fn(&i32) -> bool>);
    /// assert_eq!(removed, 2);
    /// assert!(q.is_empty());
    /// ```
    pub fn remove_all<F>(&mut self, predicate: Option<F>) -> usize
    where
        F: Fn(&T) -> bool,
    {
        match predicate {
            None => {
                // Clear entire queue, return old length
                let count = self.inner.len();
                self.inner.clear();
                count
            }
            Some(pred) => {
                // Count elements to remove, then remove them.
                // We iterate and remove matching elements one by one,
                // matching the C behavior of repeatedly calling remove_if.
                let mut count = 0usize;
                loop {
                    let pos = self.inner.iter().position(&pred);
                    match pos {
                        Some(idx) => {
                            self.inner.remove(idx);
                            count += 1;
                        }
                        None => break,
                    }
                }
                count
            }
        }
    }

    /// Retains only elements for which the predicate returns `true`.
    ///
    /// This is the idiomatic Rust counterpart to `remove_all(Some(pred))` —
    /// instead of specifying which elements to *remove*, you specify which to
    /// *keep*.
    ///
    /// # Examples
    ///
    /// ```
    /// use bluez_shared::util::queue::Queue;
    /// let mut q = Queue::new();
    /// q.push_tail(1);
    /// q.push_tail(2);
    /// q.push_tail(3);
    /// q.push_tail(4);
    /// q.retain(|x| *x % 2 == 0);
    /// assert_eq!(q.len(), 2);
    /// assert_eq!(q.pop_head(), Some(2));
    /// assert_eq!(q.pop_head(), Some(4));
    /// ```
    #[inline]
    pub fn retain<F>(&mut self, predicate: F)
    where
        F: Fn(&T) -> bool,
    {
        self.inner.retain(|item| predicate(item));
    }

    // =========================================================================
    // Query operations
    // =========================================================================

    /// Returns the number of elements in the queue.
    ///
    /// Replaces C `queue_length()` (queue.c lines 359-365). The C version
    /// returns `unsigned int`; Rust returns `usize`.
    ///
    /// # Examples
    ///
    /// ```
    /// use bluez_shared::util::queue::Queue;
    /// let mut q = Queue::new();
    /// assert_eq!(q.len(), 0);
    /// q.push_tail(1);
    /// assert_eq!(q.len(), 1);
    /// ```
    #[inline]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns `true` if the queue contains no elements.
    ///
    /// Replaces C `queue_isempty()` (queue.c lines 367-373).
    ///
    /// # Examples
    ///
    /// ```
    /// use bluez_shared::util::queue::Queue;
    /// let mut q: Queue<i32> = Queue::new();
    /// assert!(q.is_empty());
    /// q.push_tail(1);
    /// assert!(!q.is_empty());
    /// ```
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    // =========================================================================
    // Entry access
    // =========================================================================

    /// Returns a contiguous slice view of the queue contents.
    ///
    /// Replaces C `queue_get_entries()` (queue.c lines 351-357). Since
    /// [`VecDeque`] stores data in a ring buffer that may wrap around, this
    /// method calls [`VecDeque::make_contiguous()`] to ensure a single
    /// contiguous slice is available.
    ///
    /// # Examples
    ///
    /// ```
    /// use bluez_shared::util::queue::Queue;
    /// let mut q = Queue::new();
    /// q.push_tail(1);
    /// q.push_tail(2);
    /// q.push_tail(3);
    /// assert_eq!(q.as_slice(), &[1, 2, 3]);
    /// ```
    #[inline]
    pub fn as_slice(&mut self) -> &[T] {
        self.inner.make_contiguous()
    }

    /// Returns a reference to the element at the given index.
    ///
    /// Provides indexed access replacing linked-list traversal in C. Returns
    /// `None` if the index is out of bounds.
    ///
    /// # Examples
    ///
    /// ```
    /// use bluez_shared::util::queue::Queue;
    /// let mut q = Queue::new();
    /// q.push_tail(10);
    /// q.push_tail(20);
    /// q.push_tail(30);
    /// assert_eq!(q.get(0), Some(&10));
    /// assert_eq!(q.get(2), Some(&30));
    /// assert_eq!(q.get(3), None);
    /// ```
    #[inline]
    pub fn get(&self, index: usize) -> Option<&T> {
        self.inner.get(index)
    }
}

// =============================================================================
// Trait implementations
// =============================================================================

impl<T> Default for Queue<T> {
    /// Creates a new, empty queue. Equivalent to [`Queue::new()`].
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Clone> Clone for Queue<T> {
    fn clone(&self) -> Self {
        Queue { inner: self.inner.clone() }
    }
}

impl<T: std::fmt::Debug> std::fmt::Debug for Queue<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Queue").field("inner", &self.inner).finish()
    }
}

impl<T> From<Vec<T>> for Queue<T> {
    /// Creates a queue from a vector. Elements are ordered front-to-back
    /// matching the vector's index order.
    ///
    /// # Examples
    ///
    /// ```
    /// use bluez_shared::util::queue::Queue;
    /// let q: Queue<i32> = Queue::from(vec![1, 2, 3]);
    /// assert_eq!(q.peek_head(), Some(&1));
    /// assert_eq!(q.peek_tail(), Some(&3));
    /// ```
    fn from(vec: Vec<T>) -> Self {
        Queue { inner: VecDeque::from(vec) }
    }
}

impl<T> From<Queue<T>> for Vec<T> {
    /// Consumes the queue and produces a vector with elements in front-to-back
    /// order.
    ///
    /// # Examples
    ///
    /// ```
    /// use bluez_shared::util::queue::Queue;
    /// let mut q = Queue::new();
    /// q.push_tail(1);
    /// q.push_tail(2);
    /// let v: Vec<i32> = Vec::from(q);
    /// assert_eq!(v, vec![1, 2]);
    /// ```
    fn from(queue: Queue<T>) -> Self {
        Vec::from(queue.inner)
    }
}

impl<T> Extend<T> for Queue<T> {
    /// Extends the queue with the contents of an iterator, appending each
    /// element to the tail.
    ///
    /// # Examples
    ///
    /// ```
    /// use bluez_shared::util::queue::Queue;
    /// let mut q = Queue::new();
    /// q.push_tail(1);
    /// q.extend(vec![2, 3, 4]);
    /// assert_eq!(q.len(), 4);
    /// assert_eq!(q.peek_tail(), Some(&4));
    /// ```
    fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
        self.inner.extend(iter);
    }
}

impl<T> IntoIterator for Queue<T> {
    type Item = T;
    type IntoIter = std::collections::vec_deque::IntoIter<T>;

    /// Consumes the queue and returns an iterator over its elements in
    /// front-to-back order.
    ///
    /// # Examples
    ///
    /// ```
    /// use bluez_shared::util::queue::Queue;
    /// let mut q = Queue::new();
    /// q.push_tail(1);
    /// q.push_tail(2);
    /// let v: Vec<i32> = q.into_iter().collect();
    /// assert_eq!(v, vec![1, 2]);
    /// ```
    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter()
    }
}

impl<'a, T> IntoIterator for &'a Queue<T> {
    type Item = &'a T;
    type IntoIter = std::collections::vec_deque::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.iter()
    }
}

impl<'a, T> IntoIterator for &'a mut Queue<T> {
    type Item = &'a mut T;
    type IntoIter = std::collections::vec_deque::IterMut<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.iter_mut()
    }
}

// =============================================================================
// Unit tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_queue_is_empty() {
        let q: Queue<i32> = Queue::new();
        assert!(q.is_empty());
        assert_eq!(q.len(), 0);
        assert_eq!(q.peek_head(), None);
        assert_eq!(q.peek_tail(), None);
    }

    #[test]
    fn test_default_is_empty() {
        let q: Queue<i32> = Queue::default();
        assert!(q.is_empty());
    }

    #[test]
    fn test_push_tail_fifo_order() {
        let mut q = Queue::new();
        assert!(q.push_tail(1));
        assert!(q.push_tail(2));
        assert!(q.push_tail(3));

        assert_eq!(q.len(), 3);
        assert_eq!(q.peek_head(), Some(&1));
        assert_eq!(q.peek_tail(), Some(&3));

        assert_eq!(q.pop_head(), Some(1));
        assert_eq!(q.pop_head(), Some(2));
        assert_eq!(q.pop_head(), Some(3));
        assert_eq!(q.pop_head(), None);
    }

    #[test]
    fn test_push_head_lifo_order() {
        let mut q = Queue::new();
        q.push_head(1);
        q.push_head(2);
        q.push_head(3);

        assert_eq!(q.peek_head(), Some(&3));
        assert_eq!(q.peek_tail(), Some(&1));
        assert_eq!(q.pop_head(), Some(3));
        assert_eq!(q.pop_head(), Some(2));
        assert_eq!(q.pop_head(), Some(1));
    }

    #[test]
    fn test_push_after_found() {
        let mut q = Queue::new();
        q.push_tail(1);
        q.push_tail(3);

        assert!(q.push_after(&1, 2));
        assert_eq!(q.len(), 3);
        assert_eq!(q.pop_head(), Some(1));
        assert_eq!(q.pop_head(), Some(2));
        assert_eq!(q.pop_head(), Some(3));
    }

    #[test]
    fn test_push_after_at_tail() {
        let mut q = Queue::new();
        q.push_tail(1);
        q.push_tail(2);

        assert!(q.push_after(&2, 3));
        assert_eq!(q.peek_tail(), Some(&3));
        assert_eq!(q.len(), 3);
    }

    #[test]
    fn test_push_after_not_found() {
        let mut q = Queue::new();
        q.push_tail(1);
        q.push_tail(2);

        assert!(!q.push_after(&99, 3));
        assert_eq!(q.len(), 2);
    }

    #[test]
    fn test_push_after_empty_queue() {
        let mut q: Queue<i32> = Queue::new();
        assert!(!q.push_after(&1, 2));
    }

    #[test]
    fn test_pop_head_empty() {
        let mut q: Queue<i32> = Queue::new();
        assert_eq!(q.pop_head(), None);
    }

    #[test]
    fn test_peek_head_does_not_remove() {
        let mut q = Queue::new();
        q.push_tail(42);
        assert_eq!(q.peek_head(), Some(&42));
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn test_foreach_immutable() {
        let mut q = Queue::new();
        q.push_tail(1);
        q.push_tail(2);
        q.push_tail(3);

        let mut sum = 0;
        q.foreach(|x| sum += x);
        assert_eq!(sum, 6);
    }

    #[test]
    fn test_foreach_mut() {
        let mut q = Queue::new();
        q.push_tail(1);
        q.push_tail(2);
        q.push_tail(3);

        q.foreach_mut(|x| *x *= 10);
        assert_eq!(q.pop_head(), Some(10));
        assert_eq!(q.pop_head(), Some(20));
        assert_eq!(q.pop_head(), Some(30));
    }

    #[test]
    fn test_iter() {
        let mut q = Queue::new();
        q.push_tail(10);
        q.push_tail(20);
        q.push_tail(30);

        let collected: Vec<&i32> = q.iter().collect();
        assert_eq!(collected, vec![&10, &20, &30]);
    }

    #[test]
    fn test_iter_mut() {
        let mut q = Queue::new();
        q.push_tail(1);
        q.push_tail(2);

        for item in q.iter_mut() {
            *item += 100;
        }
        assert_eq!(q.peek_head(), Some(&101));
        assert_eq!(q.peek_tail(), Some(&102));
    }

    #[test]
    fn test_find_with_predicate() {
        let mut q = Queue::new();
        q.push_tail(10);
        q.push_tail(20);
        q.push_tail(30);

        assert_eq!(q.find(|x| *x > 15), Some(&20));
        assert_eq!(q.find(|x| *x > 100), None);
    }

    #[test]
    fn test_find_by_value() {
        let mut q = Queue::new();
        q.push_tail("alpha".to_string());
        q.push_tail("beta".to_string());
        q.push_tail("gamma".to_string());

        assert_eq!(q.find_by_value(&"beta".to_string()), Some(&"beta".to_string()));
        assert_eq!(q.find_by_value(&"delta".to_string()), None);
    }

    #[test]
    fn test_remove_first_match() {
        let mut q = Queue::new();
        q.push_tail(1);
        q.push_tail(2);
        q.push_tail(2);
        q.push_tail(3);

        assert!(q.remove(&2));
        assert_eq!(q.len(), 3);
        // The first 2 was removed, so order is now: [1, 2, 3]
        assert_eq!(q.pop_head(), Some(1));
        assert_eq!(q.pop_head(), Some(2));
        assert_eq!(q.pop_head(), Some(3));
    }

    #[test]
    fn test_remove_not_found() {
        let mut q = Queue::new();
        q.push_tail(1);
        assert!(!q.remove(&99));
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn test_remove_if() {
        let mut q = Queue::new();
        q.push_tail(1);
        q.push_tail(2);
        q.push_tail(3);

        let removed = q.remove_if(|x| *x == 2);
        assert_eq!(removed, Some(2));
        assert_eq!(q.len(), 2);

        let not_found = q.remove_if(|x| *x == 99);
        assert_eq!(not_found, None);
    }

    #[test]
    fn test_remove_all_with_predicate() {
        let mut q = Queue::new();
        q.push_tail(1);
        q.push_tail(2);
        q.push_tail(3);
        q.push_tail(4);
        q.push_tail(5);

        let removed = q.remove_all(Some(|x: &i32| *x % 2 == 0));
        assert_eq!(removed, 2);
        assert_eq!(q.len(), 3);

        // Remaining: 1, 3, 5
        assert_eq!(q.pop_head(), Some(1));
        assert_eq!(q.pop_head(), Some(3));
        assert_eq!(q.pop_head(), Some(5));
    }

    #[test]
    fn test_remove_all_none_clears_all() {
        let mut q = Queue::new();
        q.push_tail(1);
        q.push_tail(2);
        q.push_tail(3);

        let removed = q.remove_all(None::<fn(&i32) -> bool>);
        assert_eq!(removed, 3);
        assert!(q.is_empty());
    }

    #[test]
    fn test_remove_all_empty_queue() {
        let mut q: Queue<i32> = Queue::new();
        let removed = q.remove_all(None::<fn(&i32) -> bool>);
        assert_eq!(removed, 0);
    }

    #[test]
    fn test_retain() {
        let mut q = Queue::new();
        q.push_tail(1);
        q.push_tail(2);
        q.push_tail(3);
        q.push_tail(4);

        q.retain(|x| *x % 2 == 0);
        assert_eq!(q.len(), 2);
        assert_eq!(q.pop_head(), Some(2));
        assert_eq!(q.pop_head(), Some(4));
    }

    #[test]
    fn test_as_slice() {
        let mut q = Queue::new();
        q.push_tail(1);
        q.push_tail(2);
        q.push_tail(3);
        assert_eq!(q.as_slice(), &[1, 2, 3]);
    }

    #[test]
    fn test_as_slice_after_push_head() {
        let mut q = Queue::new();
        q.push_tail(2);
        q.push_tail(3);
        q.push_head(1);
        assert_eq!(q.as_slice(), &[1, 2, 3]);
    }

    #[test]
    fn test_get_indexed_access() {
        let mut q = Queue::new();
        q.push_tail(10);
        q.push_tail(20);
        q.push_tail(30);

        assert_eq!(q.get(0), Some(&10));
        assert_eq!(q.get(1), Some(&20));
        assert_eq!(q.get(2), Some(&30));
        assert_eq!(q.get(3), None);
    }

    #[test]
    fn test_from_vec() {
        let q: Queue<i32> = Queue::from(vec![1, 2, 3]);
        assert_eq!(q.len(), 3);
        assert_eq!(q.peek_head(), Some(&1));
        assert_eq!(q.peek_tail(), Some(&3));
    }

    #[test]
    fn test_into_vec() {
        let mut q = Queue::new();
        q.push_tail(1);
        q.push_tail(2);
        q.push_tail(3);

        let v: Vec<i32> = Vec::from(q);
        assert_eq!(v, vec![1, 2, 3]);
    }

    #[test]
    fn test_extend() {
        let mut q = Queue::new();
        q.push_tail(1);
        q.extend(vec![2, 3, 4]);
        assert_eq!(q.len(), 4);
        assert_eq!(q.peek_tail(), Some(&4));
    }

    #[test]
    fn test_into_iterator_owned() {
        let mut q = Queue::new();
        q.push_tail(1);
        q.push_tail(2);
        q.push_tail(3);

        let v: Vec<i32> = q.into_iter().collect();
        assert_eq!(v, vec![1, 2, 3]);
    }

    #[test]
    fn test_into_iterator_ref() {
        let mut q = Queue::new();
        q.push_tail(1);
        q.push_tail(2);

        let v: Vec<&i32> = (&q).into_iter().collect();
        assert_eq!(v, vec![&1, &2]);
    }

    #[test]
    fn test_into_iterator_mut_ref() {
        let mut q = Queue::new();
        q.push_tail(1);
        q.push_tail(2);

        for item in &mut q {
            *item += 10;
        }
        assert_eq!(q.pop_head(), Some(11));
        assert_eq!(q.pop_head(), Some(12));
    }

    #[test]
    fn test_clone() {
        let mut q = Queue::new();
        q.push_tail(1);
        q.push_tail(2);

        let q2 = q.clone();
        assert_eq!(q2.len(), 2);
        assert_eq!(q2.peek_head(), Some(&1));

        // Modifying clone doesn't affect original
        assert_eq!(q.peek_head(), Some(&1));
    }

    #[test]
    fn test_debug() {
        let mut q = Queue::new();
        q.push_tail(1);
        q.push_tail(2);

        let debug_str = format!("{:?}", q);
        assert!(debug_str.contains("Queue"));
        assert!(debug_str.contains("1"));
        assert!(debug_str.contains("2"));
    }

    #[test]
    fn test_generic_with_string() {
        let mut q = Queue::new();
        q.push_tail("hello".to_string());
        q.push_tail("world".to_string());

        assert_eq!(q.peek_head(), Some(&"hello".to_string()));
        assert_eq!(q.pop_head(), Some("hello".to_string()));
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn test_generic_with_custom_struct() {
        #[derive(Debug, Clone, PartialEq)]
        struct Device {
            id: u32,
            name: String,
        }

        let mut q = Queue::new();
        q.push_tail(Device { id: 1, name: "hci0".to_string() });
        q.push_tail(Device { id: 2, name: "hci1".to_string() });

        let found = q.find(|d| d.id == 2);
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "hci1");

        let removed = q.remove_if(|d| d.id == 1);
        assert!(removed.is_some());
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn test_mixed_push_pop_sequence() {
        // Simulate a realistic usage pattern matching how BlueZ uses the queue
        let mut q = Queue::new();

        // Push some items
        q.push_tail(1);
        q.push_tail(2);
        q.push_tail(3);

        // Pop one from head
        assert_eq!(q.pop_head(), Some(1));

        // Push more
        q.push_tail(4);
        q.push_head(0);

        // Current order: [0, 2, 3, 4]
        assert_eq!(q.len(), 4);
        assert_eq!(q.peek_head(), Some(&0));
        assert_eq!(q.peek_tail(), Some(&4));

        // Remove by value
        q.remove(&3);

        // Current order: [0, 2, 4]
        assert_eq!(q.len(), 3);
        assert_eq!(q.pop_head(), Some(0));
        assert_eq!(q.pop_head(), Some(2));
        assert_eq!(q.pop_head(), Some(4));
        assert!(q.is_empty());
    }

    #[test]
    fn test_remove_all_with_predicate_no_match() {
        let mut q = Queue::new();
        q.push_tail(1);
        q.push_tail(3);
        q.push_tail(5);

        // Predicate matches nothing
        let removed = q.remove_all(Some(|x: &i32| *x % 2 == 0));
        assert_eq!(removed, 0);
        assert_eq!(q.len(), 3);
    }

    #[test]
    fn test_single_element_operations() {
        let mut q = Queue::new();
        q.push_tail(42);

        assert_eq!(q.peek_head(), Some(&42));
        assert_eq!(q.peek_tail(), Some(&42));
        assert_eq!(q.len(), 1);
        assert!(!q.is_empty());
        assert_eq!(q.get(0), Some(&42));

        assert_eq!(q.pop_head(), Some(42));
        assert!(q.is_empty());
    }

    #[test]
    fn test_push_after_first_element() {
        let mut q = Queue::new();
        q.push_tail(1);
        assert!(q.push_after(&1, 2));
        assert_eq!(q.len(), 2);
        assert_eq!(q.peek_head(), Some(&1));
        assert_eq!(q.peek_tail(), Some(&2));
    }

    #[test]
    fn test_remove_if_returns_first_match() {
        let mut q = Queue::new();
        q.push_tail(2);
        q.push_tail(4);
        q.push_tail(6);

        // Should remove the first even number (2)
        let removed = q.remove_if(|x| *x % 2 == 0);
        assert_eq!(removed, Some(2));
        assert_eq!(q.len(), 2);
        assert_eq!(q.peek_head(), Some(&4));
    }

    #[test]
    fn test_find_returns_first_match() {
        let mut q = Queue::new();
        q.push_tail(10);
        q.push_tail(20);
        q.push_tail(30);

        // Should return the first element > 5
        let found = q.find(|x| *x > 5);
        assert_eq!(found, Some(&10));
    }
}
