//! Creates a machine key with a ** glob policy and prints the raw API key.
//! Used by CI to set up VWB_TEST_TOKEN for vwb integration tests.

use vaultwarden_bridge::auth;
use vaultwarden_bridge::db::{access_policies, machine_keys};

#[tokio::main]
async fn main() {
    let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    let pool = sqlx::PgPool::connect(&db_url)
        .await
        .expect("connect to postgres");

    let raw_key = auth::generate_api_key();
    let hash = auth::hash_api_key(&raw_key).expect("hash api key");

    let key = machine_keys::create(&pool, "vwb-integration-test", &hash)
        .await
        .expect("create machine key");

    access_policies::create(&pool, key.id, access_policies::TargetType::Glob, "**")
        .await
        .expect("create glob policy");

    print!("{}", raw_key);
}
