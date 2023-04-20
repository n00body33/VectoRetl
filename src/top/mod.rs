mod cmd;
mod dashboard;
mod events;
mod metrics;
mod state;

use clap::Parser;
pub use cmd::cmd;
use url::Url;

#[derive(Parser, Debug, Clone)]
#[command(rename_all = "kebab-case")]
pub struct Opts {
    /// Interval to sample metrics at, in milliseconds
    #[arg(default_value = "500", short = 'i', long)]
    interval: u32,

    /// Vector GraphQL API server endpoint
    #[arg(short, long)]
    url: Option<Url>,

    /// Humanize metrics, using numeric suffixes - e.g. 1,100 = 1.10 k, 1,000,000 = 1.00 M
    #[arg(short = 'H', long)]
    human_metrics: bool,

    /// Whether to reconnect if the underlying Vector API connection drops. By default, top will attempt to reconnect if the connection drops.
    #[arg(short, long)]
    no_reconnect: bool,

    /// Show only specified component with provided id. Multiple component id must be comma-separated.
    #[clap(short, long, value_delimiter = ',')]
    component_id: Option<Vec<String>>,
}
