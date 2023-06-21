use std::collections::HashMap;
use msal::misc::DirectoryObject;
use std::sync::Arc;
use crate::config::{HimmelblauConfig, split_username};
use log::error;

use rand::Rng;
use rand_chacha::ChaCha8Rng;
use rand::SeedableRng;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

fn gen_unique_account_uid(config: &Arc<HimmelblauConfig>, domain: &str, oid: &str) -> u32 {
    let mut hash = DefaultHasher::new();
    oid.hash(&mut hash);
    let seed = hash.finish();
    let mut rng = ChaCha8Rng::seed_from_u64(seed);

    let (min, max): (u32, u32) = config.get_idmap_range(domain);
    rng.gen_range(min..=max)
}

pub struct UserCacheEntry {
    uid: u32,
    access_token: String,
    id: String,
    display_name: String,
    user_principal_name: String,
}

impl UserCacheEntry {
    fn new(account_id: &str, access_token: &str, uid: u32, oid: &str, display_name: &str) -> UserCacheEntry {
        UserCacheEntry {
            uid: uid,
            access_token: access_token.to_string(),
            id: oid.to_string(),
            display_name: display_name.to_string(),
            user_principal_name: account_id.to_string(),
        }
    }

    pub fn get(&self, key: &str) -> Option<&String> {
        match key {
            "access_token" => Some(&self.access_token),
            "id" => Some(&self.id),
            "display_name" => Some(&self.display_name),
            "user_principal_name" => Some(&self.user_principal_name),
            &_ => None,
        }
    }

    pub fn get_uid(&self) -> u32 {
        self.uid
    }
}

pub struct GroupCacheEntry {
    gid: u32,
    id: String,
    display_name: String,
    members: Vec<String>,
}

impl GroupCacheEntry {
    fn new(gid: u32, id: &str, display_name: &str, members: Vec<String>) -> GroupCacheEntry {
        GroupCacheEntry {
            gid: gid,
            id: String::from(id),
            display_name: String::from(display_name),
            members: members,
        }
    }

    pub fn get(&self, key: &str) -> Option<&String> {
        match key {
            "id" => Some(&self.id),
            "display_name" => Some(&self.display_name),
            &_ => None,
        }
    }

    pub fn get_gid(&self) -> u32 {
        self.gid
    }

    pub fn iter_members(&self) -> impl Iterator<Item = &String> {
        self.members.iter()
    }
}

pub struct HimmelblauMemcache {
    user_cache: HashMap<String, UserCacheEntry>,
    group_cache: HashMap<String, GroupCacheEntry>,
}

impl HimmelblauMemcache {
    pub fn new() -> HimmelblauMemcache {
        HimmelblauMemcache {
            user_cache: HashMap::new(),
            group_cache: HashMap::new(),
        }
    }

    pub fn insert_user(&mut self, config: &Arc<HimmelblauConfig>, account_id: &str, access_token: &str, oid: &str, display_name: &str) {
        let (_sam, domain) = split_username(&account_id)
            .expect("Failed splitting the username");
        let uid: u32 = gen_unique_account_uid(config, domain, oid);
        let user_entry: UserCacheEntry = UserCacheEntry::new(account_id, access_token, uid, oid, display_name);
        self.user_cache.insert(String::from(account_id), user_entry);
    }

    pub fn insert_user_groups(&mut self, config: &Arc<HimmelblauConfig>, domain: &str, groups: Vec<DirectoryObject>, member: &str) {
        for group in groups {
            let oid = group.get("id")
                .expect("Failed fetching group id");
            if self.group_cache.contains_key(oid) {
                // Add to the existing cache entry
                if let Some(group_entry) = self.group_cache.get_mut(oid) {
                    let display_name = group.get("display_name")
                        .expect("Failed fetching group display_name");
                    group_entry.display_name = String::from(display_name);
                    if !group_entry.members.contains(&member.to_string()) {
                        group_entry.members.push(member.to_string());
                    }
                } else {
                    error!("Failed fetching existing group from cache");
                }
            } else {
                let display_name = group.get("display_name")
                    .expect("Failed fetching group display_name");
                let gid: u32 = gen_unique_account_uid(config, domain, oid);
                let members: Vec<String> = vec![member.to_string()];
                let group_entry: GroupCacheEntry = GroupCacheEntry::new(gid, oid, display_name, members);
                self.group_cache.insert(oid.to_string(), group_entry);
            }
        }
    }

    pub fn get_user(&self, account_id: &str) -> Option<&UserCacheEntry> {
        self.user_cache.get(account_id)
    }

    pub fn user_iter(&self) -> impl Iterator<Item = (&String, &UserCacheEntry)> {
        self.user_cache.iter()
    }

    pub fn get_group(&self, oid: &str) -> Option<&GroupCacheEntry> {
        self.group_cache.get(oid)
    }

    pub fn group_iter(&self) -> impl Iterator<Item = (&String, &GroupCacheEntry)> {
        self.group_cache.iter()
    }
}
