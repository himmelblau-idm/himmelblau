/*
   Unix Azure Entra ID implementation
   Copyright (C) David Mulder <dmulder@samba.org> 2025

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
use std::collections::HashMap;

pub struct UserMap {
    forward: HashMap<String, String>,
    reverse: HashMap<String, String>,
}

impl UserMap {
    pub fn new(user_map_file: &str) -> UserMap {
        let mut forward = HashMap::new();
        let mut reverse = HashMap::new();

        // User map lines are colon seperated.
        if let Ok(lines) = std::fs::read_to_string(user_map_file) {
            for line in lines.lines() {
                if line.trim_start().starts_with("#") || line.trim().is_empty() {
                    continue;
                }
                let mut it = line.splitn(2, ':');
                let local = it.next().map(str::trim).unwrap_or("").to_string();
                // The lowercase SPN names are because these are case-insensitive in Entra Id
                let upn = it.next().map(str::trim).unwrap_or("").to_lowercase();

                if local.is_empty() || upn.is_empty() {
                    continue;
                }
                if forward.contains_key(&local) {
                    continue;
                }
                if reverse.contains_key(&upn) {
                    continue;
                }

                forward.insert(local.clone(), upn.clone());
                reverse.insert(upn, local);
            }
        }

        UserMap { forward, reverse }
    }

    pub fn get_upn_from_local(&self, username: &str) -> Option<String> {
        self.forward.get(username).cloned()
    }

    pub fn get_local_from_upn(&self, upn: &str) -> Option<String> {
        self.reverse.get(upn).cloned()
    }

    pub fn get_id_overrides(&self) -> Vec<String> {
        self.forward.keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn create_temp_file(contents: &str) -> String {
        let file_path = format!("/tmp/himmelblau_user_map_test_{}.txt", uuid::Uuid::new_v4());
        fs::write(&file_path, contents).expect("Failed to write temp file");
        file_path
    }

    #[test]
    fn test_user_map_basic_parsing() {
        let contents = "localuser:user@example.com";
        let temp_file = create_temp_file(contents);
        let map = UserMap::new(&temp_file);

        assert_eq!(
            map.get_upn_from_local("localuser"),
            Some("user@example.com".to_string())
        );
        assert_eq!(
            map.get_local_from_upn("user@example.com"),
            Some("localuser".to_string())
        );
        fs::remove_file(&temp_file).ok();
    }

    #[test]
    fn test_user_map_multiple_entries() {
        let contents = "alice:alice@example.com\nbob:bob@example.com\ncharlie:charlie@example.com";
        let temp_file = create_temp_file(contents);
        let map = UserMap::new(&temp_file);

        assert_eq!(
            map.get_upn_from_local("alice"),
            Some("alice@example.com".to_string())
        );
        assert_eq!(
            map.get_upn_from_local("bob"),
            Some("bob@example.com".to_string())
        );
        assert_eq!(
            map.get_upn_from_local("charlie"),
            Some("charlie@example.com".to_string())
        );
        assert_eq!(map.get_id_overrides().len(), 3);
        fs::remove_file(&temp_file).ok();
    }

    #[test]
    fn test_user_map_skips_comments() {
        let contents = "# This is a comment\nalice:alice@example.com\n   # Indented comment\nbob:bob@example.com";
        let temp_file = create_temp_file(contents);
        let map = UserMap::new(&temp_file);

        assert_eq!(
            map.get_upn_from_local("alice"),
            Some("alice@example.com".to_string())
        );
        assert_eq!(
            map.get_upn_from_local("bob"),
            Some("bob@example.com".to_string())
        );
        assert_eq!(map.get_id_overrides().len(), 2);
        fs::remove_file(&temp_file).ok();
    }

    #[test]
    fn test_user_map_skips_empty_lines() {
        let contents = "alice:alice@example.com\n\n\nbob:bob@example.com\n   \n";
        let temp_file = create_temp_file(contents);
        let map = UserMap::new(&temp_file);

        assert_eq!(map.get_id_overrides().len(), 2);
        fs::remove_file(&temp_file).ok();
    }

    #[test]
    fn test_user_map_upn_lowercased() {
        let contents = "localuser:User@Example.COM";
        let temp_file = create_temp_file(contents);
        let map = UserMap::new(&temp_file);

        // UPN is lowercased during parsing
        assert_eq!(
            map.get_upn_from_local("localuser"),
            Some("user@example.com".to_string())
        );
        // Lookup must use lowercase
        assert_eq!(
            map.get_local_from_upn("user@example.com"),
            Some("localuser".to_string())
        );
        // Original case lookup fails
        assert_eq!(map.get_local_from_upn("User@Example.COM"), None);
        fs::remove_file(&temp_file).ok();
    }

    #[test]
    fn test_user_map_local_name_case_preserved() {
        let contents = "LocalUser:user@example.com";
        let temp_file = create_temp_file(contents);
        let map = UserMap::new(&temp_file);

        // Local name case is preserved
        assert_eq!(
            map.get_upn_from_local("LocalUser"),
            Some("user@example.com".to_string())
        );
        // Different case doesn't match
        assert_eq!(map.get_upn_from_local("localuser"), None);
        fs::remove_file(&temp_file).ok();
    }

    #[test]
    fn test_user_map_duplicate_local_skipped() {
        // First entry wins for duplicate local names
        let contents = "alice:alice1@example.com\nalice:alice2@example.com";
        let temp_file = create_temp_file(contents);
        let map = UserMap::new(&temp_file);

        assert_eq!(
            map.get_upn_from_local("alice"),
            Some("alice1@example.com".to_string())
        );
        assert_eq!(map.get_id_overrides().len(), 1);
        fs::remove_file(&temp_file).ok();
    }

    #[test]
    fn test_user_map_duplicate_upn_skipped() {
        // First entry wins for duplicate UPNs
        let contents = "alice:user@example.com\nbob:user@example.com";
        let temp_file = create_temp_file(contents);
        let map = UserMap::new(&temp_file);

        assert_eq!(
            map.get_local_from_upn("user@example.com"),
            Some("alice".to_string())
        );
        // bob is skipped because UPN already exists
        assert_eq!(map.get_upn_from_local("bob"), None);
        fs::remove_file(&temp_file).ok();
    }

    #[test]
    fn test_user_map_skips_incomplete_lines() {
        // Lines without colon or empty parts are skipped
        let contents = "nocolon\n:onlyupn@example.com\nlocalonly:\nalice:alice@example.com";
        let temp_file = create_temp_file(contents);
        let map = UserMap::new(&temp_file);

        assert_eq!(map.get_id_overrides().len(), 1);
        assert_eq!(
            map.get_upn_from_local("alice"),
            Some("alice@example.com".to_string())
        );
        fs::remove_file(&temp_file).ok();
    }

    #[test]
    fn test_user_map_whitespace_trimmed() {
        let contents = "  alice  :  alice@example.com  ";
        let temp_file = create_temp_file(contents);
        let map = UserMap::new(&temp_file);

        assert_eq!(
            map.get_upn_from_local("alice"),
            Some("alice@example.com".to_string())
        );
        fs::remove_file(&temp_file).ok();
    }

    #[test]
    fn test_user_map_missing_file() {
        let map = UserMap::new("/nonexistent/path/to/file.txt");

        // Missing file results in empty map
        assert_eq!(map.get_id_overrides().len(), 0);
        assert_eq!(map.get_upn_from_local("anything"), None);
    }

    #[test]
    fn test_user_map_colon_in_upn() {
        // UPN can contain colons (splitn(2) handles this)
        let contents = "alice:alice:special@example.com";
        let temp_file = create_temp_file(contents);
        let map = UserMap::new(&temp_file);

        assert_eq!(
            map.get_upn_from_local("alice"),
            Some("alice:special@example.com".to_string())
        );
        fs::remove_file(&temp_file).ok();
    }
}
