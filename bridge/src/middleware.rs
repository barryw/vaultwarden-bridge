use axum::{
    extract::{ConnectInfo, Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use ipnet::IpNet;
use std::net::{IpAddr, SocketAddr};

pub fn ip_allowed(ip: &IpAddr, cidrs: &[IpNet]) -> bool {
    cidrs.iter().any(|cidr| cidr.contains(ip))
}

pub async fn cidr_filter_api(
    State(cidrs): State<Vec<IpNet>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if !ip_allowed(&addr.ip(), &cidrs) {
        tracing::warn!(ip = %addr.ip(), "API request denied by CIDR filter");
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(next.run(request).await)
}

pub async fn cidr_filter_ui(
    State(cidrs): State<Vec<IpNet>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if !ip_allowed(&addr.ip(), &cidrs) {
        tracing::warn!(ip = %addr.ip(), "UI request denied by CIDR filter");
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(next.run(request).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_ip_in_cidr_list() {
        let cidrs: Vec<IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        let ip: IpAddr = "10.1.2.3".parse().unwrap();
        assert!(ip_allowed(&ip, &cidrs));
    }

    #[test]
    fn test_ip_not_in_cidr_list() {
        let cidrs: Vec<IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        assert!(!ip_allowed(&ip, &cidrs));
    }

    #[test]
    fn test_empty_cidr_list_denies_all() {
        let cidrs: Vec<IpNet> = vec![];
        let ip: IpAddr = "10.1.2.3".parse().unwrap();
        assert!(!ip_allowed(&ip, &cidrs));
    }
}
