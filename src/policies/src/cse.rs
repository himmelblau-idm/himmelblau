/* Provides a trait which specifies a Client Side Extension for applying
 * Intune policy.
 */
use crate::policies::Policy;
use anyhow::Result;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;

#[async_trait]
pub trait CSE: Send + Sync {
    fn new(graph_url: &str, access_token: &str, id: &str) -> Self
    where
        Self: Sized;
    async fn process_group_policy(
        &self,
        deleted_gpo_list: Vec<Arc<dyn Policy>>,
        changed_gpo_list: Vec<Arc<dyn Policy>>,
    ) -> Result<bool>;
    async fn rsop(&self, gpo: Arc<dyn Policy>) -> Result<HashMap<String, String>>;
}
