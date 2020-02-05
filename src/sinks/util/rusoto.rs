use crate::dns::Resolver;
use hyper::client::connect::HttpConnector;
use hyper_openssl::{
    openssl::ssl::{SslConnector, SslMethod},
    HttpsConnector,
};
use rusoto_core::{CredentialsError, HttpClient, Region};
use rusoto_credential::{DefaultCredentialsProvider, ProvideAwsCredentials};
use rusoto_firehose::KinesisFirehoseClient;
use rusoto_logs::CloudWatchLogsClient;
use rusoto_sts::{StsAssumeRoleSessionCredentialsProvider, StsClient};
use snafu::{ResultExt, Snafu};

pub type Client = HttpClient<HttpsConnector<HttpConnector<Resolver>>>;

#[derive(Debug, Snafu)]
enum RusotoError {
    #[snafu(display("{}", source))]
    InvalidAWSCredentials { source: CredentialsError },
}

pub fn client(resolver: Resolver) -> crate::Result<Client> {
    let mut http = HttpConnector::new_with_resolver(resolver);
    http.enforce_http(false);

    let ssl = SslConnector::builder(SslMethod::tls())?;
    let https = HttpsConnector::with_connector(http, ssl)?;

    Ok(HttpClient::from_connector(https))
}

pub trait RusotoNewClient {
    fn new_client<P>(client: Client, credentials_provider: P, region: Region) -> Self
    where
        P: ProvideAwsCredentials + Send + Sync + 'static,
        P::Future: Send;
}

pub fn create_client<T: RusotoNewClient>(
    region: Region,
    assume_role: Option<String>,
    resolver: Resolver,
) -> crate::Result<T> {
    let client = client(resolver)?;

    if let Some(role) = assume_role {
        let sts = StsClient::new(region.clone());

        let provider = StsAssumeRoleSessionCredentialsProvider::new(
            sts,
            role,
            "default".to_owned(),
            None,
            None,
            None,
            None,
        );

        let creds = rusoto_credential::AutoRefreshingProvider::new(provider)
            .context(InvalidAWSCredentials)?;
        Ok(T::new_client(client, creds, region))
    } else {
        let creds = DefaultCredentialsProvider::new().context(InvalidAWSCredentials)?;
        Ok(T::new_client(client, creds, region))
    }
}

impl RusotoNewClient for CloudWatchLogsClient {
    fn new_client<P>(client: Client, creds: P, region: Region) -> Self
    where
        P: ProvideAwsCredentials + Send + Sync + 'static,
        P::Future: Send,
    {
        Self::new_with(client, creds, region)
    }
}

impl RusotoNewClient for KinesisFirehoseClient {
    fn new_client<P>(client: Client, creds: P, region: Region) -> Self
    where
        P: ProvideAwsCredentials + Send + Sync + 'static,
        P::Future: Send,
    {
        Self::new_with(client, creds, region)
    }
}
