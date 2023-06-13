== Items that need completed ==

* A persistent user/auth cache to disk (which is different from the MS auth cache).
* Is it possible to run the daemon not as root?
* Create MS auth cache using mapdb (https://github.com/jankotek/mapdb). This will require either writing our own Rust database implementation, or calling into this Java library (MS calls this Java library). Auth cache is stored in ~/.config/microsoft-identity-broker/account-data.db. This would need to be populated for each user which logs in. This allows MS apps to auth automatically (such as signing users into MS Edge).
