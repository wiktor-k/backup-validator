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
