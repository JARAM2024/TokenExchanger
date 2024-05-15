#[global_allocator]
static GLOBAL: jemallocator::Jemalloc = jemallocator::Jemalloc;

use std::env;

use dotenv::dotenv;

use pingora::server::configuration::Opt;
use pingora::server::{Server, ShutdownWatch};
use pingora::services::background::{background_service, BackgroundService};
use pingora::services::{listening::Service as ListeningService, Service};

use async_trait::async_trait;
use structopt::StructOpt;
use tokio::time::interval;

use std::time::Duration;

mod app;
mod service;

pub struct HaksulBackgroundService;
#[async_trait]
impl BackgroundService for HaksulBackgroundService {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let mut period = interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    // shutdown
                    break;
                }
                _ = period.tick() => {
                    // do some work
                    // ...
                }
            }
        }
    }
}

use pingora::tls::pkey::{PKey, Private};
use pingora::tls::x509::X509;
struct DynamicCert {
    cert: X509,
    key: PKey<Private>,
}

impl DynamicCert {
    fn new(cert: &str, key: &str) -> Box<Self> {
        let cert_bytes = std::fs::read(cert).unwrap();
        let cert = X509::from_pem(&cert_bytes).unwrap();

        let key_bytes = std::fs::read(key).unwrap();
        let key = PKey::private_key_from_pem(&key_bytes).unwrap();
        Box::new(DynamicCert { cert, key })
    }
}

#[async_trait]
impl pingora::listeners::TlsAccept for DynamicCert {
    async fn certificate_callback(&self, ssl: &mut pingora::tls::ssl::SslRef) {
        use pingora::tls::ext;
        ext::ssl_use_certificate(ssl, &self.cert).unwrap();
        ext::ssl_use_private_key(ssl, &self.key).unwrap();
    }
}

fn main() {
    dotenv().expect("Please use .env file for configurations.");

    let opt = Some(Opt::from_args());
    let mut my_server = Server::new(opt).unwrap();
    my_server.bootstrap();

    let cert_path = format!(
        "{}/proxy.crt",
        env::var("PROXY_MANIFEST_DIR").expect("PROXY_MANIFEST_DIR should exist in .env")
    );
    let key_path = format!(
        "{}/proxy.key",
        env::var("PROXY_MANIFEST_DIR").expect("PROXY_MANIFEST_DIR should exist in .env")
    );

    let dynamic_cert = DynamicCert::new(&cert_path, &key_path);
    let mut tls_settings = pingora::listeners::TlsSettings::with_callbacks(dynamic_cert).unwrap();
    tls_settings
        .set_max_proto_version(Some(pingora::tls::ssl::SslVersion::TLS1_2))
        .unwrap();
    tls_settings.enable_h2();

    let proxy_service = service::proxy::proxy_service(&my_server.configuration);
    let proxy_ssl_service =
        service::proxy::proxy_service_tls(&my_server.configuration, tls_settings);

    let background_service = background_service("example", HaksulBackgroundService {});

    let prometheus_endpoint =
        env::var("PROMETHEUS_ENDPOINT").expect("PROMETHEUS_ENDPOINT should exist in .env");
    let mut prometheus_service_http = ListeningService::prometheus_http_service();
    prometheus_service_http.add_tcp(&prometheus_endpoint);

    let services: Vec<Box<dyn Service>> = vec![
        Box::new(proxy_service),
        Box::new(proxy_ssl_service),
        Box::new(prometheus_service_http),
        Box::new(background_service),
    ];
    my_server.add_services(services);
    my_server.run_forever();
}
