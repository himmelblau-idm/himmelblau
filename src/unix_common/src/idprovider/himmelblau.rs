use async_trait::async_trait;
use msal::authentication::{PublicClientApplication, REQUIRES_MFA, NO_CONSENT, NO_SECRET, NO_GROUP_CONSENT, UnixUserToken};
use himmelblau_policies::policies::apply_group_policy;
use crate::constants::{DEFAULT_APP_ID, DEFAULT_CONFIG_PATH};
use std::sync::Arc;
use tokio::sync::RwLock;
use crate::config::HimmelblauConfig;
use msal::misc::{request_user_groups, DirectoryObject};
use uuid::Uuid;
use super::interface::{GroupToken, Id, IdProvider, IdpError, UserToken};
use std::collections::HashMap;
use crate::config::split_username;

use rand::Rng;
use rand_chacha::ChaCha8Rng;
use rand::SeedableRng;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

async fn gen_unique_account_uid(rconfig: &Arc<RwLock<HimmelblauConfig>>, domain: &str, oid: &str) -> u32 {
    let config = rconfig.read();
    let mut hash = DefaultHasher::new();
    oid.hash(&mut hash);
    let seed = hash.finish();
    let mut rng = ChaCha8Rng::seed_from_u64(seed);

    let (min, max): (u32, u32) = config.await.get_idmap_range(domain);
    rng.gen_range(min..=max)
}

pub struct HimmelblauMultiProvider {
    config: Arc<RwLock<HimmelblauConfig>>,
    providers: RwLock<HashMap<String, HimmelblauProvider>>,
}

impl HimmelblauMultiProvider {
    pub fn new() -> Self {
        HimmelblauMultiProvider {
            config: RwLock::new(
                HimmelblauConfig::new(DEFAULT_CONFIG_PATH).unwrap()
            ).into(),
            providers: RwLock::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl IdProvider for HimmelblauMultiProvider {
    async fn provider_authenticate(&self) -> Result<(), IdpError> {
        /* Irrelevant to AAD */
        Ok(())
    }

    async fn unix_user_get(&self, _id: &Id) -> Result<UserToken, IdpError> {
        /* AAD doesn't permit user listing (must use cache entries from auth) */
        Err(IdpError::NotFound)
    }

    async fn unix_user_authenticate(
        &self,
        id: &Id,
        cred: &str,
    ) -> Result<Option<UserToken>, IdpError> {
        let account_id = id.to_string().clone();
        match split_username(&account_id) {
            Some((_sam, domain)) => {
                self.check_insert_provider(domain).await;
                let providers = self.providers.read().await;
                match providers.get(domain) {
                    Some(provider) => provider.unix_user_authenticate(id, cred).await,
                    None => Err(IdpError::NotFound),
                }
            },
            None => {
                Err(IdpError::NotFound)
            }
        }
    }

    async fn unix_group_get(&self, _id: &Id) -> Result<GroupToken, IdpError> {
        /* AAD doesn't permit group listing (must use cache entries from auth) */
        Err(IdpError::NotFound)
    }
}

impl HimmelblauMultiProvider {
    async fn check_insert_provider(&self, domain: &str) {
        let mut providers = self.providers.write().await;
        if !providers.contains_key(domain) {
            let config = self.config.read().await;
            let (_tenant_id, authority_url, graph) = config.get_authority_url(domain).await;
            let app_id = config.get_app_id(domain);
            let app = PublicClientApplication::new(&app_id, authority_url.as_str());
            providers.insert(domain.to_string(),
                HimmelblauProvider::new(
                    app,
                    self.config.clone(),
                    domain.to_string(),
                    authority_url,
                    graph,
                    app_id
                )
            );
        }
    }
}

pub struct HimmelblauProvider {
    client: RwLock<PublicClientApplication>,
    config: Arc<RwLock<HimmelblauConfig>>,
    domain: String,
    authority_url: String,
    graph_url: String,
    app_id: String,
}

impl HimmelblauProvider {
    pub fn new(client: PublicClientApplication, config: Arc<RwLock<HimmelblauConfig>>, domain: String, authority_url: String, graph_url: String, app_id: String) -> Self {
        HimmelblauProvider {
            client: RwLock::new(client),
            config: config.clone(),
            domain: domain.to_string(),
            authority_url: authority_url.to_string(),
            graph_url: graph_url.to_string(),
            app_id: app_id.to_string(),
        }
    }
}

#[async_trait]
impl IdProvider for HimmelblauProvider {
    // Needs .read on all types except re-auth.

    async fn provider_authenticate(&self) -> Result<(), IdpError> {
        /* Irrelevant to AAD */
        Ok(())
    }

    async fn unix_user_get(&self, _id: &Id) -> Result<UserToken, IdpError> {
        /* AAD doesn't permit user listing (must use cache entries from auth) */
        Err(IdpError::NotFound)
    }

    async fn unix_user_authenticate(
        &self,
        id: &Id,
        cred: &str,
    ) -> Result<Option<UserToken>, IdpError> {
        let account_id = id.to_string().clone();
        let mut scopes = vec![];
        if self.app_id != DEFAULT_APP_ID {
            scopes.push("GroupMember.Read.All");
        }
        let mut token = match self.client.write().await.acquire_token_by_username_password(&account_id, cred, scopes) {
            Ok(token) => token,
            Err(_e) => return Err(IdpError::NotFound),
        };
        // We may have been denied GroupMember.Read.All, try again without it
        if token.errors.contains(&NO_GROUP_CONSENT) || token.errors.contains(&NO_CONSENT) {
            debug!("Failed auth with GroupMember.Read.All permissions.");
            debug!("Group memberships will be missing display names.");
            debug!("{}: {}", token.error, token.error_description);
            token = match self.client.write().await.acquire_token_by_username_password(&account_id, cred, vec![]) {
                Ok(token) => token,
                Err(_e) => return Err(IdpError::NotFound),
            };
        }
        match token.access_token {
            Some(_) => {
                info!("Authentication successful for user '{}'", account_id);
                /* Process Group Policy (spawn non-blocking process to prevent auth timeout),
                 * if it is enabled via config */
                if self.config.read().await.get_apply_policy() {
                    let graph_url = self.graph_url.clone();
                    // The access_token is safe to unwrap because we just validated it's existance
                    let access_token = token.access_token.as_ref().unwrap().clone();
                    let uuid = token.uuid.to_string();
                    Some(tokio::spawn(async move {
                        match apply_group_policy(&graph_url, &access_token, &uuid).await {
                            Ok(res) => {
                                if res {
                                    info!("Successfully applied group policies");
                                } else {
                                    error!("Failed to apply group policies");
                                }
                            },
                            Err(res) => {
                                error!("Failed to apply group policies: {}", res);
                            },
                        }
                    }));
                }
                Ok(Some(self.user_token_from_unix_user_token(token).await))
            },
            None => {
                info!("Authentication failed for user '{}'", account_id);
                if token.errors.contains(&REQUIRES_MFA) {
                    info!("Azure AD application requires MFA");
                    //TODO: Attempt an interactive auth via the browser
                }
                if token.errors.contains(&NO_CONSENT) {
                    let url = format!("{}/adminconsent?client_id={}", self.authority_url, self.app_id);
                    error!("Azure AD application requires consent, either from tenant, or from user, go to: {}", url);
                }
                if token.errors.contains(&NO_SECRET) {
                    let url = "https://learn.microsoft.com/en-us/azure/active-directory/develop/scenario-desktop-app-registration#redirect-uris";
                    error!("Azure AD application requires enabling 'Allow public client flows'. {}", url);
                }
                error!("{}: {}", token.error, token.error_description);
                Err(IdpError::NotFound)
            }
        }
    }

    async fn unix_group_get(&self, _id: &Id) -> Result<GroupToken, IdpError> {
        /* AAD doesn't permit group listing (must use cache entries from auth) */
        Err(IdpError::NotFound)
    }
}

impl HimmelblauProvider {
    async fn user_token_from_unix_user_token(&self, value: UnixUserToken) -> UserToken {
        let config = self.config.read();
        let mut groups: Vec<GroupToken>;
        match value.access_token {
            Some(access_token) => {
                groups = match request_user_groups(&self.graph_url, &access_token).await {
                    Ok(groups) => {
                        let mut gt_groups = vec![];
                        for g in groups {
                            gt_groups.push(self.group_token_from_directory_object(g).await);
                        }
                        gt_groups
                    },
                    Err(_e) => {
                        debug!("Failed fetching user groups for {}", &value.spn);
                        vec![]
                    },
                };
            },
            None => {
                debug!("Failed fetching user groups for {}", &value.spn);
                groups = vec![];
            }
        };
        let sshkeys: Vec<String> = vec![];
        let valid = true;
        let gidnumber = gen_unique_account_uid(&self.config, &self.domain, &value.uuid.to_string()).await;
        // Add the fake primary group
        groups.push(
            GroupToken {
                name: value.spn.clone(),
                spn: value.spn.clone(),
                uuid: value.uuid.clone(),
                gidnumber,
            }
        );

        UserToken {
            name: value.spn.clone(),
            spn: value.spn,
            uuid: value.uuid,
            gidnumber,
            displayname: value.displayname,
            shell: Some(config.await.get_shell(Some(&self.domain))),
            groups,
            sshkeys,
            valid,
        }
    }

    async fn group_token_from_directory_object(&self, value: DirectoryObject) -> GroupToken {
        let name = value.get("display_name")
            .expect("Failed retrieving group display_name");
        let id = value.get("id")
            .expect("Failed retrieving group uuid");
        let gidnumber = gen_unique_account_uid(&self.config, &self.domain, id).await;
        GroupToken {
            name: name.clone(),
            spn: name.to_string(),
            uuid: Uuid::parse_str(id)
                .expect("Failed parsing user uuid"),
            gidnumber,
        }
    }
}
