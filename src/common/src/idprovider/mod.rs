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
use crate::config::{split_username, HimmelblauConfig};
use crate::db::KeyStoreTxn;
use crate::idprovider::himmelblau::HimmelblauProvider;
use crate::idprovider::interface::{
    tpm, AuthCacheAction, AuthCredHandler, AuthRequest, AuthResult, CacheState, GroupToken, Id,
    IdProvider, IdpError, UpnVerdict, UserToken, UserTokenState,
};
use crate::idprovider::oidc_router::OidcRouter;
use crate::unix_proto::PamAuthRequest;
use ::himmelblau::auth::UserToken as UnixUserToken;
use ::himmelblau::graph::Graph;
use ::himmelblau::BrokerClientApplication;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use idmap::Idmap;
use libkrimes::proto::KerberosCredentials;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::{broadcast, Mutex};

pub(crate) mod common;
pub mod himmelblau;
pub(crate) mod oidc_router;
pub mod okta;
pub mod openidconnect;

pub mod interface;

#[allow(clippy::large_enum_variant)]
enum Providers {
    Oidc(OidcRouter),
    Himmelblau(HimmelblauProvider),
}

pub struct IdProviderProxy {
    config: Arc<Mutex<HimmelblauConfig>>,
    provider: Arc<Providers>,
}

impl IdProviderProxy {
    pub async fn new<D: KeyStoreTxn + Send>(
        config_filename: &str,
        keystore: &mut D,
    ) -> Result<Self> {
        let config = match HimmelblauConfig::new(Some(config_filename)) {
            Ok(config) => Arc::new(Mutex::new(config)),
            Err(e) => return Err(anyhow!("{}", e)),
        };
        let idmap = match Idmap::new() {
            Ok(idmap) => Arc::new(Mutex::new(idmap)),
            Err(e) => return Err(anyhow!("{:?}", e)),
        };

        let domain = config.lock().await.get_configured_entra_domain();
        let oidc_issuer_url = config.lock().await.get_oidc_issuer_url();
        let provider = match (oidc_issuer_url, domain) {
            (None, None) => {
                return Err(anyhow!("No provider was configured!"));
            }
            (Some(_), domain) => {
                if let Some(domain) = domain {
                    warn!(
                        "Both OIDC and Entra ID domain '{}' are configured, \
                         the domain is ignored",
                        domain
                    );
                }
                let provider = OidcRouter::new(&config, "oidc", &idmap)
                    .await
                    .map_err(|e| {
                        error!("Failed initializing OIDC provider: {:?}", e);
                        anyhow!("{:?}", e)
                    })?;
                Providers::Oidc(provider)
            }
            (_, Some(domain)) => {
                debug!("Adding provider for domain {}", domain);
                let ignored: Vec<String> = config
                    .lock()
                    .await
                    .get_configured_entra_domains()
                    .into_iter()
                    .filter(|d| d != &domain)
                    .collect();
                if !ignored.is_empty() {
                    warn!(
                        "Multiple domains are not supported, using '{}' and \
                         ignoring: {}",
                        domain,
                        ignored.join(", ")
                    );
                }
                let (authority_host, tenant_id, graph_url, odc_provider, app_id, ip_versions) = {
                    let cfg = config.lock().await;
                    (
                        cfg.get_authority_host(&domain),
                        cfg.get_tenant_id(&domain),
                        cfg.get_graph_url(&domain),
                        cfg.get_odc_provider(&domain),
                        cfg.get_app_id(&domain),
                        cfg.get_ip_versions(),
                    )
                };
                let request_timeout = config.lock().await.get_request_timeout();
                let graph = Graph::new(
                    &odc_provider,
                    &domain,
                    Some(&authority_host),
                    tenant_id.as_deref(),
                    graph_url.as_deref(),
                    Duration::from_secs(request_timeout),
                    &ip_versions,
                )
                .await
                .map_err(|e| {
                    error!("Failed initializing provider: {:?}", e);
                    anyhow!("Failed to initialize the provider")
                })?;
                let app = BrokerClientApplication::new(
                    None,
                    app_id.as_deref(),
                    None,
                    None,
                    Duration::from_secs(request_timeout),
                    &ip_versions,
                )
                .map_err(|e| {
                    error!("Failed initializing provider: {:?}", e);
                    anyhow!("{:?}", e)
                })?;
                let provider = HimmelblauProvider::new(app, &config, &domain, graph, &idmap)
                    .map_err(|e| {
                        error!("Failed to initialize the provider: {:?}", e);
                        anyhow!("Failed to initialize the provider")
                    })?;
                {
                    // A client write lock is required here.
                    let mut client = provider.client().lock().await;
                    if let Ok(transport_key) =
                        provider.fetch_loadable_transport_key_from_keystore(keystore)
                    {
                        client.set_transport_key(transport_key);
                    }
                    if let Ok(cert_key) = provider.fetch_loadable_cert_key_from_keystore(keystore) {
                        client.set_cert_key(cert_key);
                    }
                }
                Providers::Himmelblau(provider)
            }
        };

        let proxy = IdProviderProxy {
            config: config.clone(),
            provider: Arc::new(provider),
        };

        // Spawn periodic cookie clearing loop (Fixes bugs #591 and #491)
        // FIXME: The client should spawn its own cookie clearing task
        let providers_ref = proxy.provider.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(12 * 60 * 60)).await;
                match providers_ref.as_ref() {
                    Providers::Oidc(_) => {}
                    Providers::Himmelblau(provider) => {
                        let app = provider.client().lock().await;
                        app.clear_cookies();
                    }
                }
            }
        });

        Ok(proxy)
    }
    async fn find_provider(&self, domain: Option<&str>) -> Result<&Providers, IdpError> {
        let provider = self.provider.as_ref();
        let found = match (domain, provider) {
            (_, Providers::Oidc(_)) => true,
            (Some(d), Providers::Himmelblau(h)) => {
                /* NEVER introduce a new tenant here: Advisory GHSA-q746-m2wv-qh4v.
                 * An alias is only accepted when it resolves to the domain of
                 * the provider we already configured. */
                d == h.domain()
                    || self
                        .config
                        .lock()
                        .await
                        .get_primary_domain_from_alias(d)
                        .await
                        .is_some_and(|p| p.as_str() == h.domain())
            }
            (None, Providers::Himmelblau(_)) => false,
        };
        if found {
            Ok(provider)
        } else {
            Err(IdpError::NotFound {
                what: format!("domain: {}", domain.unwrap_or("<empty>")),
                where_: "providers".to_string(),
            })
        }
    }
}

fn upn_domain(account_id: &str) -> Option<&str> {
    split_username(account_id).map(|(_, domain)| domain)
}

fn account_domain<'a>(id: &'a Id, old_token: Option<&'a UserToken>) -> Option<&'a str> {
    match (old_token, id) {
        (Some(token), _) => upn_domain(token.spn.as_str()),
        (None, Id::Name(name)) => upn_domain(name),
        (None, Id::Gid(_)) => None,
    }
}

#[async_trait]
impl IdProvider for IdProviderProxy {
    async fn offline_break_glass(&self, ttl: Option<u64>) -> Result<(), IdpError> {
        match self.provider.as_ref() {
            Providers::Oidc(provider) => provider.offline_break_glass(ttl).await,
            Providers::Himmelblau(provider) => provider.offline_break_glass(ttl).await,
        }
    }

    async fn check_online(&self, tpm: &mut tpm::provider::BoxedDynTpm, now: SystemTime) -> bool {
        match self.provider.as_ref() {
            Providers::Oidc(provider) => provider.check_online(tpm, now).await,
            Providers::Himmelblau(provider) => provider.check_online(tpm, now).await,
        }
    }

    async fn probe_online(&self, account_id: Option<&str>, now: SystemTime) -> bool {
        let provider = match account_id {
            Some(id) => {
                let domain = upn_domain(id);
                let Ok(provider) = self.find_provider(domain).await else {
                    return false;
                };
                provider
            }
            None => self.provider.as_ref(),
        };
        match provider {
            Providers::Oidc(provider) => provider.probe_online(account_id, now).await,
            Providers::Himmelblau(provider) => provider.probe_online(account_id, now).await,
        }
    }

    async fn unix_user_access<D: KeyStoreTxn + Send>(
        &self,
        id: &Id,
        scopes: Vec<String>,
        old_token: Option<&UserToken>,
        client_id: Option<String>,
        redirect_uri: Option<String>,
        req_cnf: Option<String>,
        keystore: &mut D,
        tpm: &mut tpm::provider::BoxedDynTpm,
        machine_key: &tpm::structures::StorageKey,
    ) -> Result<UnixUserToken, IdpError> {
        let domain = account_domain(id, old_token);
        let provider = self.find_provider(domain).await?;
        match provider {
            Providers::Oidc(provider) => {
                provider
                    .unix_user_access(
                        id,
                        scopes,
                        old_token,
                        client_id,
                        redirect_uri,
                        req_cnf,
                        keystore,
                        tpm,
                        machine_key,
                    )
                    .await
            }
            Providers::Himmelblau(provider) => {
                provider
                    .unix_user_access(
                        id,
                        scopes,
                        old_token,
                        client_id,
                        redirect_uri,
                        req_cnf,
                        keystore,
                        tpm,
                        machine_key,
                    )
                    .await
            }
        }
    }

    async fn unix_user_tgts<D: KeyStoreTxn + Send>(
        &self,
        id: &Id,
        old_token: Option<&UserToken>,
        keystore: &mut D,
        tpm: &mut tpm::provider::BoxedDynTpm,
        machine_key: &tpm::structures::StorageKey,
    ) -> (
        Option<Box<KerberosCredentials>>,
        Option<Box<KerberosCredentials>>,
        Option<String>,
        Option<String>,
    ) {
        let domain = account_domain(id, old_token);
        let Ok(provider) = self.find_provider(domain).await else {
            return (None, None, None, None);
        };
        match provider {
            Providers::Oidc(provider) => {
                provider
                    .unix_user_tgts(id, old_token, keystore, tpm, machine_key)
                    .await
            }
            Providers::Himmelblau(provider) => {
                provider
                    .unix_user_tgts(id, old_token, keystore, tpm, machine_key)
                    .await
            }
        }
    }

    async fn unix_user_prt_cookie<D: KeyStoreTxn + Send>(
        &self,
        id: &Id,
        old_token: Option<&UserToken>,
        sso_nonce: Option<&str>,
        keystore: &mut D,
        tpm: &mut tpm::provider::BoxedDynTpm,
        machine_key: &tpm::structures::StorageKey,
    ) -> Result<String, IdpError> {
        let domain = account_domain(id, old_token);
        let provider = self.find_provider(domain).await?;
        match provider {
            Providers::Oidc(provider) => {
                provider
                    .unix_user_prt_cookie(id, old_token, sso_nonce, keystore, tpm, machine_key)
                    .await
            }
            Providers::Himmelblau(provider) => {
                provider
                    .unix_user_prt_cookie(id, old_token, sso_nonce, keystore, tpm, machine_key)
                    .await
            }
        }
    }

    async fn change_auth_token<D: KeyStoreTxn + Send>(
        &self,
        account_id: &str,
        token: &UnixUserToken,
        new_tok: &str,
        keystore: &mut D,
        tpm: &mut tpm::provider::BoxedDynTpm,
        machine_key: &tpm::structures::StorageKey,
    ) -> Result<bool, IdpError> {
        let domain = upn_domain(account_id);
        let provider = self.find_provider(domain).await?;
        match provider {
            Providers::Oidc(provider) => {
                provider
                    .change_auth_token(account_id, token, new_tok, keystore, tpm, machine_key)
                    .await
            }
            Providers::Himmelblau(provider) => {
                provider
                    .change_auth_token(account_id, token, new_tok, keystore, tpm, machine_key)
                    .await
            }
        }
    }

    async fn unix_user_verify_upn(
        &self,
        account_id: &str,
        tpm: &mut tpm::provider::BoxedDynTpm,
        machine_key: &tpm::structures::StorageKey,
    ) -> UpnVerdict {
        match self.find_provider(upn_domain(account_id)).await {
            Ok(Providers::Himmelblau(provider)) => {
                provider
                    .unix_user_verify_upn(account_id, tpm, machine_key)
                    .await
            }
            _ => UpnVerdict::Unknown,
        }
    }

    async fn unix_user_get<D: KeyStoreTxn + Send>(
        &self,
        id: &Id,
        old_token: Option<&UserToken>,
        keystore: &mut D,
        tpm: &mut tpm::provider::BoxedDynTpm,
        machine_key: &tpm::structures::StorageKey,
    ) -> Result<UserTokenState, IdpError> {
        /* AAD doesn't permit user listing (must use cache entries from auth) */
        let domain = account_domain(id, old_token);
        let provider = self.find_provider(domain).await?;
        match provider {
            Providers::Oidc(provider) => {
                provider
                    .unix_user_get(id, old_token, keystore, tpm, machine_key)
                    .await
            }
            Providers::Himmelblau(provider) => {
                provider
                    .unix_user_get(id, old_token, keystore, tpm, machine_key)
                    .await
            }
        }
    }

    async fn unix_user_online_auth_init<D: KeyStoreTxn + Send>(
        &self,
        account_id: &str,
        token: Option<&UserToken>,
        service: &str,
        no_hello_pin: bool,
        force_reauth: bool,
        keystore: &mut D,
        tpm: &mut tpm::provider::BoxedDynTpm,
        machine_key: &tpm::structures::StorageKey,
        shutdown_rx: &broadcast::Receiver<()>,
    ) -> Result<(AuthRequest, AuthCredHandler), IdpError> {
        let domain = upn_domain(account_id);
        let provider = self.find_provider(domain).await?;
        match provider {
            Providers::Oidc(provider) => {
                provider
                    .unix_user_online_auth_init(
                        account_id,
                        token,
                        service,
                        no_hello_pin,
                        force_reauth,
                        keystore,
                        tpm,
                        machine_key,
                        shutdown_rx,
                    )
                    .await
            }
            Providers::Himmelblau(provider) => {
                provider
                    .unix_user_online_auth_init(
                        account_id,
                        token,
                        service,
                        no_hello_pin,
                        force_reauth,
                        keystore,
                        tpm,
                        machine_key,
                        shutdown_rx,
                    )
                    .await
            }
        }
    }

    async fn unix_user_online_auth_step<D: KeyStoreTxn + Send>(
        &self,
        account_id: &str,
        old_token: &UserToken,
        service: &str,
        no_hello_pin: bool,
        cred_handler: &mut AuthCredHandler,
        pam_next_req: PamAuthRequest,
        keystore: &mut D,
        tpm: &mut tpm::provider::BoxedDynTpm,
        machine_key: &tpm::structures::StorageKey,
        shutdown_rx: &broadcast::Receiver<()>,
    ) -> Result<(AuthResult, AuthCacheAction), IdpError> {
        let domain = upn_domain(account_id);
        let provider = self.find_provider(domain).await?;
        match provider {
            Providers::Oidc(provider) => {
                provider
                    .unix_user_online_auth_step(
                        account_id,
                        old_token,
                        service,
                        no_hello_pin,
                        cred_handler,
                        pam_next_req,
                        keystore,
                        tpm,
                        machine_key,
                        shutdown_rx,
                    )
                    .await
            }
            Providers::Himmelblau(provider) => {
                provider
                    .unix_user_online_auth_step(
                        account_id,
                        old_token,
                        service,
                        no_hello_pin,
                        cred_handler,
                        pam_next_req,
                        keystore,
                        tpm,
                        machine_key,
                        shutdown_rx,
                    )
                    .await
            }
        }
    }

    async fn unix_user_offline_auth_init<D: KeyStoreTxn + Send>(
        &self,
        account_id: &str,
        token: Option<&UserToken>,
        service: &str,
        no_hello_pin: bool,
        keystore: &mut D,
    ) -> Result<(AuthRequest, AuthCredHandler), IdpError> {
        let domain = upn_domain(account_id);
        let provider = self.find_provider(domain).await?;
        match provider {
            Providers::Oidc(provider) => {
                provider
                    .unix_user_offline_auth_init(account_id, token, service, no_hello_pin, keystore)
                    .await
            }
            Providers::Himmelblau(provider) => {
                provider
                    .unix_user_offline_auth_init(account_id, token, service, no_hello_pin, keystore)
                    .await
            }
        }
    }

    async fn unix_user_offline_auth_step<D: KeyStoreTxn + Send>(
        &self,
        account_id: &str,
        token: &UserToken,
        cred_handler: &mut AuthCredHandler,
        pam_next_req: PamAuthRequest,
        keystore: &mut D,
        tpm: &mut tpm::provider::BoxedDynTpm,
        machine_key: &tpm::structures::StorageKey,
        online_at_init: bool,
    ) -> Result<AuthResult, IdpError> {
        let domain = upn_domain(account_id);
        let provider = self.find_provider(domain).await?;
        match provider {
            Providers::Oidc(provider) => {
                provider
                    .unix_user_offline_auth_step(
                        account_id,
                        token,
                        cred_handler,
                        pam_next_req,
                        keystore,
                        tpm,
                        machine_key,
                        online_at_init,
                    )
                    .await
            }
            Providers::Himmelblau(provider) => {
                provider
                    .unix_user_offline_auth_step(
                        account_id,
                        token,
                        cred_handler,
                        pam_next_req,
                        keystore,
                        tpm,
                        machine_key,
                        online_at_init,
                    )
                    .await
            }
        }
    }

    async fn unix_user_try_unseal<D: KeyStoreTxn + Send>(
        &self,
        account_id: &str,
        cred: &str,
        keystore: &mut D,
        tpm: &mut tpm::provider::BoxedDynTpm,
        machine_key: &tpm::structures::StorageKey,
        online: bool,
    ) -> Result<bool, IdpError> {
        let domain = upn_domain(account_id);
        let provider = self.find_provider(domain).await?;
        match provider {
            Providers::Oidc(provider) => {
                provider
                    .unix_user_try_unseal(account_id, cred, keystore, tpm, machine_key, online)
                    .await
            }
            Providers::Himmelblau(provider) => {
                provider
                    .unix_user_try_unseal(account_id, cred, keystore, tpm, machine_key, online)
                    .await
            }
        }
    }

    async fn unix_group_get(
        &self,
        _id: &Id,
        _tpm: &mut tpm::provider::BoxedDynTpm,
    ) -> Result<GroupToken, IdpError> {
        /* AAD doesn't permit group listing (must use cache entries from auth) */
        debug!("Group fetching not supported");
        Err(IdpError::BadRequest)
    }

    async fn get_cachestate(&self, account_id: Option<&str>) -> CacheState {
        let provider = match account_id {
            Some(id) => {
                let domain = upn_domain(id);
                let Ok(provider) = self.find_provider(domain).await else {
                    return CacheState::Offline;
                };
                provider
            }
            None => self.provider.as_ref(),
        };
        match provider {
            Providers::Oidc(provider) => provider.get_cachestate(account_id).await,
            Providers::Himmelblau(provider) => provider.get_cachestate(account_id).await,
        }
    }

    async fn export_broker_prts(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut all: HashMap<String, Vec<u8>> = HashMap::new();
        if let Providers::Himmelblau(p) = self.provider.as_ref() {
            let data = p.export_broker_prts().await?;
            all.insert(p.domain().to_owned(), data);
        }
        serde_json::to_vec(&all)
    }

    async fn import_broker_prts(&self, data: &[u8]) -> Result<(), serde_json::Error> {
        let all: HashMap<String, Vec<u8>> = serde_json::from_slice(data)?;
        if let Providers::Himmelblau(provider) = self.provider.as_ref() {
            for (domain, blob) in &all {
                if domain == provider.domain() {
                    if let Err(e) = provider.import_broker_prts(blob).await {
                        tracing::warn!("Failed to import PRTs for domain {}: {:?}", domain, e);
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upn_domain_requires_a_single_at() {
        assert_eq!(upn_domain("alice@example.com"), Some("example.com"));
        assert_eq!(upn_domain("alice"), None);
        assert_eq!(upn_domain("alice@example.com@evil.com"), None);
    }

    #[test]
    fn account_domain_from_id() {
        let id = Id::Name("alice@example.com".to_string());
        assert_eq!(account_domain(&id, None), Some("example.com"));
        let id = Id::Name("alice".to_string());
        assert_eq!(account_domain(&id, None), None);
        assert_eq!(account_domain(&Id::Gid(1000), None), None);
    }
}
