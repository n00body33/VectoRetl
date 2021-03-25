use async_graphql::{Enum, SimpleObject};

#[derive(Enum, Debug, Copy, Clone, PartialEq, Eq)]
/// Log event notification type
pub enum LogEventNotificationType {
    /// A component was found that matched the provided pattern
    Matched,
    /// There isn't currently a component that matches this pattern
    NotMatched,
}

#[derive(Debug, SimpleObject)]
/// A notification regarding logs events observation
pub struct LogEventNotification {
    /// Name of the component associated with the notification
    component_name: String,

    /// Log event notification type
    notification: LogEventNotificationType,
}

impl LogEventNotification {
    pub fn new(component_name: &str, notification: LogEventNotificationType) -> Self {
        Self {
            component_name: component_name.to_string(),
            notification,
        }
    }
}
