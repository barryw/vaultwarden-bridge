use crate::db::access_policies::{AccessPolicy, TargetType};

pub fn evaluate_access(
    policies: &[AccessPolicy],
    requested_key: &str,
    item_collection_ids: &[String],
) -> bool {
    policies.iter().any(|p| match p.target_type {
        TargetType::Item => p.target_value == requested_key,
        TargetType::Glob => glob_match::glob_match(&p.target_value, requested_key),
        TargetType::Collection => item_collection_ids
            .iter()
            .any(|cid| cid == &p.target_value),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::access_policies::{AccessPolicy, TargetType};

    fn policy(target_type: TargetType, target_value: &str) -> AccessPolicy {
        AccessPolicy {
            id: uuid::Uuid::new_v4(),
            machine_key_id: uuid::Uuid::new_v4(),
            target_type,
            target_value: target_value.to_string(),
            created_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn test_exact_item_match() {
        let policies = vec![policy(TargetType::Item, "prod/db/password")];
        assert!(evaluate_access(&policies, "prod/db/password", &[]));
    }

    #[test]
    fn test_exact_item_no_match() {
        let policies = vec![policy(TargetType::Item, "prod/db/password")];
        assert!(!evaluate_access(&policies, "staging/db/password", &[]));
    }

    #[test]
    fn test_glob_match_single_level() {
        let policies = vec![policy(TargetType::Glob, "prod/*")];
        assert!(evaluate_access(&policies, "prod/password", &[]));
    }

    #[test]
    fn test_glob_match_multi_level() {
        let policies = vec![policy(TargetType::Glob, "prod/**")];
        assert!(evaluate_access(&policies, "prod/db/password", &[]));
    }

    #[test]
    fn test_glob_no_match() {
        let policies = vec![policy(TargetType::Glob, "prod/**")];
        assert!(!evaluate_access(&policies, "staging/db/password", &[]));
    }

    #[test]
    fn test_collection_match() {
        let policies = vec![policy(TargetType::Collection, "col-123")];
        let item_collections = vec!["col-123".to_string()];
        assert!(evaluate_access(&policies, "anything", &item_collections));
    }

    #[test]
    fn test_no_policies_denies() {
        assert!(!evaluate_access(&[], "prod/db/password", &[]));
    }
}
