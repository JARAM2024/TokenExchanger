use crate::app::proxy::Endpoint;
use crate::app::proxy::ProxyApp;
use pingora::listeners::TlsSettings;
use pingora::server::configuration::ServerConf;
use pingora_core::services::listening::Service;
use pingora_proxy::http_proxy_service_with_name;
use pingora_proxy::HttpProxy;
use std::sync::Arc;

pub fn proxy_service(server_conf: &Arc<ServerConf>) -> Service<HttpProxy<ProxyApp>> {
    let endpoint = Endpoint {};
    endpoint.load_configuration("http_entries.json");

    let addr = std::env::var("HTTP_PROXY_ENDPOINT")
        .expect("Please append HTTP_PROXY_ENDPOINT env variable.");
    let proxy_password = std::env::var("HTTP_PROXY_PASSWORD")
        .expect("Please append HTTP_PROXY_PASSWORD env variable.");

    let mut service = http_proxy_service_with_name(
        server_conf,
        ProxyApp::new(endpoint, proxy_password),
        "HTTP Proxy Service",
    );
    service.add_tcp(&addr);

    service
}

pub fn proxy_service_tls(
    server_conf: &Arc<ServerConf>,
    tls_settings: TlsSettings,
) -> Service<HttpProxy<ProxyApp>> {
    let endpoint = Endpoint {};
    endpoint.load_configuration("https_entries.json");

    let addr = std::env::var("HTTPS_PROXY_ENDPOINT")
        .expect("Please append HTTPS_PROXY_ENDPOINT env variable.");
    let proxy_password = std::env::var("HTTPS_PROXY_PASSWORD")
        .expect("Please append HTTPS_PROXY_PASSWORD env variable.");

    let mut service = http_proxy_service_with_name(
        server_conf,
        ProxyApp::new(endpoint, proxy_password),
        "HTTPS Proxy Service",
    );
    service.add_tls_with_settings(&addr, None, tls_settings);

    service
}
