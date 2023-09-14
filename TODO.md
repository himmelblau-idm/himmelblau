# Items that need completed

* Create MS auth cache using mapdb (https://github.com/jankotek/mapdb). This will require either writing our own Rust database implementation, or calling into this Java library (MS calls this Java library). Auth cache is stored in ~/.config/microsoft-identity-broker/account-data.db. This would need to be populated for each user which logs in. This allows MS apps to auth automatically (such as signing users into MS Edge).
  * Perhaps creating the mapdb isn't necessary. It actually seems likely that MS apps are receiving auth tokens from the Broker daemon somehow. We should implement the Broker code for providing tokens.
* himmelblau should only authenticate to configured domains.

## Major Requirements

* Device enrollment.
