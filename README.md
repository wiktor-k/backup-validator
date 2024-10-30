# NetHSM backup

Small library and a CLI utility to validate and browse NetHSM backups.

## Library

```rust
# fn main() -> testresult::TestResult {
use std::collections::HashMap;
use nethsm_backup::Backup;

let backup = std::fs::File::open("tests/nethsm.backup-file.bkp")?;

let decryptor = Backup::parse(backup)?.decrypt(b"my-very-unsafe-backup-passphrase")?;

assert_eq!(decryptor.version()?, [0]);

let map = decryptor.items_iter().collect::<Result<HashMap<_, _>, _>>()?;
assert_eq!(map.len(), 46);
assert_eq!(map["/config/unattended-boot"], vec![49]);
assert_eq!(map["/config/version"], vec![48]);

# Ok(()) }
```

## CLI

Listing fields in a backup file:

```sh
$ cargo run --release --features=cli -- --password tests/password --backup tests/*.bkp list
   Compiling nethsm-backup v0.1.0 (/home/wiktor/src/vlv/backup-validator)
    Finished `release` profile [optimized] target(s) in 0.35s
     Running `/home/wiktor/tmp/cargo/release/main --password tests/password --backup tests/nethsm.backup-file.bkp list`
/.initialized
/authentication/.version
/authentication/admin
/authentication/admin1
/authentication/backup1
/authentication/metrics1
/authentication/namespace1~admin1
/authentication/namespace1~operator1
...
```

Dumping one field:

```sh
$ cargo run --release --features=cli -- --password tests/password --backup tests/*.bkp dump /config/version | xxd
    Finished `release` profile [optimized] target(s) in 0.02s
     Running `/home/wiktor/tmp/cargo/release/main --password tests/password --backup tests/nethsm.backup-file.bkp dump /config/version`
00000000: 30                                       0
```
