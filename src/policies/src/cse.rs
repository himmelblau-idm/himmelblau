/*
   Unix Azure Entra ID implementation
   Copyright (C) David Mulder <dmulder@samba.org> 2024

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

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
