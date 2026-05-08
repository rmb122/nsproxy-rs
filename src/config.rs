use std::net::SocketAddr;

#[derive(Debug, Clone)]
pub enum ProxyType {
    Socks5,
    Http,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub proxy_type: ProxyType,
    pub proxy_addr: SocketAddr,
    pub proxy_auth: Option<(String, String)>,
    pub command: Vec<String>,
}
