mod agent;
mod relay;

use std::time::Duration;

use tokio::time::{MissedTickBehavior, interval};

pub use agent::serve as serve_agent;
pub use relay::serve as serve_relay;

fn heartbeat() -> tokio::time::Interval {
    let mut interval = interval(Duration::from_secs(30));
    interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
    interval
}
