# 1Password

Deadbolt reads 1Password once, from an export:

```sh
deadbolt import ~/Downloads/1PasswordExport.1pux   # File › Export › (account) › 1PUX
deadbolt import --dry-run ~/Downloads/1PasswordExport.1pux
```

Categories map to Deadbolt's item types, documents and attachments come along
(up to 10 MiB each), and items already in the vault are skipped, so importing
the same export again adds only what's new. Each imported item records which
1Password item it came from in its hidden `source` register. Delete the
export afterwards: it isn't encrypted.

The live one-way mirror (`deadbolt sync 1password`, through the 1Password
CLI) was removed: the one-shot import is the only 1Password path left.
