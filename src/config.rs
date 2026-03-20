use ipnet::IpNet;
use std::env;

#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub bw_server_url: String,
    pub bw_email: String,
    pub bw_password: String,
    pub bw_serve_port: u16,
    pub admin_username: String,
    pub admin_password: String,
    pub ui_allow_cidrs: Vec<IpNet>,
    pub api_allow_cidrs: Vec<IpNet>,
    pub listen_port: u16,
}

pub fn parse_cidrs(s: &str) -> Result<Vec<IpNet>, ipnet::AddrParseError> {
    if s.trim().is_empty() {
        return Ok(vec![]);
    }
    s.split(',').map(|c| c.trim().parse::<IpNet>()).collect()
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            database_url: env::var("DATABASE_URL")?,
            bw_server_url: env::var("BW_SERVER_URL")?,
            bw_email: env::var("BW_EMAIL")?,
            bw_password: env::var("BW_PASSWORD")?,
            bw_serve_port: env::var("BW_SERVE_PORT")
                .unwrap_or_else(|_| "8087".to_string())
                .parse()?,
            admin_username: env::var("BRIDGE_ADMIN_USERNAME")?,
            admin_password: env::var("BRIDGE_ADMIN_PASSWORD")?,
            ui_allow_cidrs: parse_cidrs(&env::var("BRIDGE_UI_ALLOW_CIDRS").unwrap_or_default())?,
            api_allow_cidrs: parse_cidrs(&env::var("BRIDGE_API_ALLOW_CIDRS").unwrap_or_default())?,
            listen_port: env::var("BRIDGE_LISTEN_PORT")
                .unwrap_or_else(|_| "8080".to_string())
                .parse()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cidrs_valid() {
        let cidrs = parse_cidrs("10.0.0.0/8,192.168.1.0/24").unwrap();
        assert_eq!(cidrs.len(), 2);
    }

    #[test]
    fn test_parse_cidrs_empty_denies_all() {
        let cidrs = parse_cidrs("").unwrap();
        assert!(cidrs.is_empty());
    }

    #[test]
    fn test_parse_cidrs_invalid() {
        assert!(parse_cidrs("not-a-cidr").is_err());
    }
}
