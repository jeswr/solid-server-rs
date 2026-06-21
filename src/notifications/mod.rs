// AUTHORED-BY Claude Opus 4.8
//! Solid Notifications (WebSocketChannel2023) — an in-process subscription registry + AS2.0 emit.
//!
//! This module is **net-new and isolated**: it does NOT modify the storage layer. The LDP write path
//! makes a SINGLE [`NotificationHub::notify`] call after a successful mutation (an emit hook), and the
//! discovery + subscription endpoints ([`ws`]) advertise + serve the WebSocketChannel2023 channel.
//!
//! ## What this implements (WebSocketChannel2023)
//! - **Discovery** — a storage-description document + `Link` headers advertise the subscription
//!   service URL ([`ws::storage_description_handler`], [`ws::link_headers`]).
//! - **Subscribe** — a client `POST`s a JSON-LD channel request naming a `topic`; the server returns
//!   a channel description whose `receiveFrom` is a `ws(s)://` URL ([`ws::subscribe_handler`]).
//! - **Receive** — connecting to `receiveFrom` upgrades to a WebSocket and registers the connection
//!   under the topic IRI ([`ws::receive_handler`]); the server pushes an AS2.0 notification whenever
//!   the topic (or its container membership) changes.
//!
//! ## Concurrency model (the make-the-call decision, documented)
//! The registry is a `Mutex<HashMap<topic_iri, broadcast::Sender<Arc<str>>>>`:
//! - A `tokio::sync::broadcast` channel per watched topic IRI gives clean 1-N fan-out: an emit is a
//!   single `send` and every live receiver gets it. This is the idiomatic axum chat-broadcast pattern.
//! - The notification body is built + serialised ONCE per emit (an `Arc<str>`) and the SAME `Arc` is
//!   broadcast to all subscribers — no per-subscriber re-serialisation.
//! - A `broadcast::Sender` with NO receivers is pruned lazily on the next emit (a `send` returns
//!   `Err(SendError)` when there are zero receivers) so a torn-down subscription cannot leak the map
//!   entry. A receiver that lags past the buffer drops the oldest frame (`RecvError::Lagged`) — the
//!   client must reconcile on reconnect (the documented missed-update safety contract), which is the
//!   correct trade-off for a notification stream vs. unbounded memory growth.
//! - The `Mutex` is held only for the O(1) map get/insert/prune; the actual fan-out (`send`) is a
//!   lock-free broadcast push, so emit does not serialise behind subscriber I/O.
//!
//! ## Auth (fail-closed; WAC seam is M2-next)
//! Subscription is gated on an AUTHENTICATED WebID (no anonymous subscriptions) — the subscribe POST
//! runs behind the same DPoP auth middleware as the LDP routes. **Known limitation:** per-resource
//! WAC authorization of a subscription (does this WebID have `read` on the topic?) is NOT yet
//! enforced — it is a `// M2-next:` seam gated on `sparq#992` (the SPARQ access-control design), the
//! same blocker as the LDP read/write authorization. A subscriber today must be authenticated but is
//! not yet ACL-checked per-resource. This is a documented gap, not a silent one.

pub mod activity;
pub mod ws;

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::{broadcast, Mutex};

pub use activity::{ActivityType, AS2_CONTEXT, NOTIFICATIONS_CONTEXT};

/// How many notifications a per-topic broadcast channel buffers before a slow receiver starts
/// dropping the oldest (`RecvError::Lagged`). Small on purpose: notifications are change SIGNALS, not
/// a durable log — a client that falls this far behind should reconcile by re-reading, not replay a
/// long backlog (the missed-update-safety contract in the skill). 64 absorbs a normal burst without
/// holding unbounded memory per topic.
const TOPIC_BUFFER: usize = 64;

/// The in-process subscription registry + AS2.0 notification emitter.
///
/// Cloning a [`NotificationHub`] shares the SAME underlying registry (it is an `Arc` inside), so the
/// LDP state and the notification routes both hold a handle to one hub.
#[derive(Clone, Default)]
pub struct NotificationHub {
    /// topic IRI -> the broadcast sender that fans a notification to that topic's subscribers.
    topics: Arc<Mutex<HashMap<String, broadcast::Sender<Arc<str>>>>>,
}

impl NotificationHub {
    /// A fresh, empty hub.
    pub fn new() -> Self {
        Self::default()
    }

    /// Subscribe to a topic IRI: returns a [`broadcast::Receiver`] that yields every notification
    /// emitted for `topic` from this point on. Creates the topic's channel on first subscription.
    pub async fn subscribe(&self, topic: &str) -> broadcast::Receiver<Arc<str>> {
        let mut topics = self.topics.lock().await;
        match topics.get(topic) {
            Some(tx) => tx.subscribe(),
            None => {
                let (tx, rx) = broadcast::channel(TOPIC_BUFFER);
                topics.insert(topic.to_string(), tx);
                rx
            }
        }
    }

    /// The number of LIVE subscribers for a topic (0 if the topic has no channel). Test/observability
    /// aid — also the basis of the lazy prune (a topic with 0 receivers is dropped on the next emit).
    pub async fn subscriber_count(&self, topic: &str) -> usize {
        let topics = self.topics.lock().await;
        topics.get(topic).map(|tx| tx.receiver_count()).unwrap_or(0)
    }

    /// Emit an AS2.0 notification for a change to `resource`.
    ///
    /// This is THE emit hook the LDP write path calls after a successful mutation. It fans the
    /// notification to:
    /// 1. subscribers of `resource` itself (the changed resource), and
    /// 2. subscribers of `parent` — the container — as a MEMBERSHIP activity (`Add` on create,
    ///    `Remove` on delete), so a client watching a container learns its membership changed.
    ///
    /// `activity` is the resource-level activity (Create/Update/Delete). The container membership
    /// activity is DERIVED: a `Create` ⇒ `Add` on the parent, a `Delete` ⇒ `Remove`; an `Update`
    /// does not change membership, so no parent notification is emitted for it. (Make-the-call
    /// mapping, documented in [`activity`].)
    pub async fn notify(&self, resource: &str, activity: ActivityType, parent: Option<&str>) {
        // 1. The resource's own subscribers: the resource-level activity, `object` = the resource.
        let resource_body: Arc<str> = Arc::from(activity::build_notification_string(
            activity, resource, None,
        ));
        self.fan_out(resource, resource_body).await;

        // 2. The parent container's subscribers: a membership activity (Add/Remove) iff membership
        //    actually changed. An Update edits content without changing the container's `ldp:contains`
        //    set, so it does NOT notify the parent (avoids spurious container churn).
        if let Some(container) = parent {
            let membership = match activity {
                ActivityType::Create => Some(ActivityType::Add),
                ActivityType::Delete => Some(ActivityType::Remove),
                // Update / (already-membership) Add / Remove: no derived parent membership change.
                ActivityType::Update | ActivityType::Add | ActivityType::Remove => None,
            };
            if let Some(member_activity) = membership {
                // AS2 Add/Remove: the container is the `target` collection, the child is the `object`.
                let body: Arc<str> = Arc::from(activity::build_notification_string(
                    member_activity,
                    resource,
                    Some(container),
                ));
                self.fan_out(container, body).await;
            }
        }
    }

    /// Send a pre-built notification frame to a topic's subscribers, pruning a dead (0-receiver)
    /// channel. Holds the lock only for the map lookup + the (lock-free) broadcast `send`.
    async fn fan_out(&self, topic: &str, body: Arc<str>) {
        let mut topics = self.topics.lock().await;
        if let Some(tx) = topics.get(topic) {
            // `send` returns Err only when there are zero receivers — the subscription was torn down
            // (all sockets closed) without the entry being removed. Prune it so the map cannot leak.
            if tx.send(body).is_err() {
                topics.remove(topic);
            }
        }
        // No entry ⇒ nobody is watching this topic; nothing to do (and nothing to allocate).
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn subscribe_then_notify_delivers_to_that_topic() {
        let hub = NotificationHub::new();
        let mut rx = hub.subscribe("https://pod.example/a").await;
        assert_eq!(hub.subscriber_count("https://pod.example/a").await, 1);

        hub.notify("https://pod.example/a", ActivityType::Update, None)
            .await;

        let frame = rx.try_recv().expect("a notification was delivered");
        assert!(frame.contains("\"type\":\"Update\""), "{frame}");
        assert!(
            frame.contains("\"object\":\"https://pod.example/a\""),
            "{frame}"
        );
    }

    #[tokio::test]
    async fn notify_does_not_reach_unrelated_subscribers() {
        let hub = NotificationHub::new();
        let mut other = hub.subscribe("https://pod.example/other").await;

        hub.notify("https://pod.example/a", ActivityType::Update, None)
            .await;

        // The unrelated topic got NOTHING.
        assert!(
            other.try_recv().is_err(),
            "an unrelated subscriber must not receive the notification"
        );
    }

    #[tokio::test]
    async fn create_fans_to_resource_and_parent_membership() {
        let hub = NotificationHub::new();
        let mut resource_rx = hub.subscribe("https://pod.example/c/child").await;
        let mut container_rx = hub.subscribe("https://pod.example/c/").await;

        hub.notify(
            "https://pod.example/c/child",
            ActivityType::Create,
            Some("https://pod.example/c/"),
        )
        .await;

        // The resource subscriber sees the Create.
        let r = resource_rx.try_recv().expect("resource notified");
        assert!(r.contains("\"type\":\"Create\""), "{r}");

        // The container subscriber sees a membership Add naming the container as `target`.
        let c = container_rx.try_recv().expect("container notified");
        assert!(c.contains("\"type\":\"Add\""), "{c}");
        assert!(c.contains("\"target\":\"https://pod.example/c/\""), "{c}");
        assert!(
            c.contains("\"object\":\"https://pod.example/c/child\""),
            "{c}"
        );
    }

    #[tokio::test]
    async fn update_does_not_notify_parent_container() {
        let hub = NotificationHub::new();
        let mut container_rx = hub.subscribe("https://pod.example/c/").await;

        hub.notify(
            "https://pod.example/c/child",
            ActivityType::Update,
            Some("https://pod.example/c/"),
        )
        .await;

        // An UPDATE does not change membership ⇒ the container is NOT notified.
        assert!(
            container_rx.try_recv().is_err(),
            "an Update must not emit a parent membership notification"
        );
    }

    #[tokio::test]
    async fn delete_fans_membership_remove_to_parent() {
        let hub = NotificationHub::new();
        let mut container_rx = hub.subscribe("https://pod.example/c/").await;

        hub.notify(
            "https://pod.example/c/child",
            ActivityType::Delete,
            Some("https://pod.example/c/"),
        )
        .await;

        let c = container_rx.try_recv().expect("container notified");
        assert!(c.contains("\"type\":\"Remove\""), "{c}");
    }

    #[tokio::test]
    async fn dropped_subscriber_is_pruned_on_next_emit_no_leak() {
        let hub = NotificationHub::new();
        let rx = hub.subscribe("https://pod.example/a").await;
        assert_eq!(hub.subscriber_count("https://pod.example/a").await, 1);

        // Tear down the only subscriber (simulates a closed WebSocket dropping its Receiver).
        drop(rx);
        assert_eq!(hub.subscriber_count("https://pod.example/a").await, 0);

        // The next emit prunes the now-deadtopic entry — no map leak.
        hub.notify("https://pod.example/a", ActivityType::Update, None)
            .await;

        let topics = hub.topics.lock().await;
        assert!(
            !topics.contains_key("https://pod.example/a"),
            "a 0-receiver topic must be pruned on emit, not leaked"
        );
    }

    #[tokio::test]
    async fn notify_with_no_subscribers_is_a_noop() {
        let hub = NotificationHub::new();
        // No panic, no entry created for a topic nobody watches.
        hub.notify("https://pod.example/nobody", ActivityType::Update, None)
            .await;
        assert_eq!(hub.subscriber_count("https://pod.example/nobody").await, 0);
    }
}
