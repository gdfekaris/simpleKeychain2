# Backup Security: Extra Precautions

The [main README](../README.md#backup--restore) covers everyday export and import. This guide is for when you want to be thorough about minimizing exposure of backup plaintext.

## Prefer SK2B when you don't need a human-readable CSV

The plaintext only ever exists inside `sk2 import`, which holds it in zeroed memory. The GPG path produces a plaintext CSV the moment you decrypt it, and from that point on secure deletion is your problem.

## If you decrypt a GPG export, decrypt to a RAM-backed filesystem

Decrypting to RAM avoids writing plaintext to a physical disk where it could be recovered after deletion.

Linux (`/tmp` is usually a tmpfs — confirm with `df -T /tmp` before relying on it):

```
gpg -d sk2-export.csv.gpg > /tmp/credentials.csv
# use the file, then:
shred -u /tmp/credentials.csv
```

macOS: `/tmp` is ordinary disk, not a RAM-backed filesystem, so the command above buys you nothing there. Either prefer SK2B, or create an actual RAM disk first:

```
diskutil erasevolume APFS ramdisk $(hdiutil attach -nomount ram://65536)
gpg -d sk2-export.csv.gpg > /Volumes/ramdisk/credentials.csv
# use the file, then:
hdiutil detach /Volumes/ramdisk
```

Windows (requires a RAM disk tool like [ImDisk](https://sourceforge.net/projects/imdisk-toolkit/)):

```
gpg -d sk2-export.csv.gpg > R:\credentials.csv
# use the file, then delete it — or simply unmount the RAM disk
```

## Securely delete any decrypted CSV

Regular deletion only removes the directory entry — the data remains on disk until overwritten.

Linux:

```
shred -u credentials.csv
```

macOS ships no `shred`. Install GNU coreutils (`brew install coreutils`, then `gshred -u`) — or avoid needing it by decrypting only to RAM, as above.

Windows (built-in `cipher /w` wipes free space in a directory after you delete the file):

```
del credentials.csv
cipher /w:C:\path\to\directory
```

Note: secure deletion is ineffective on copy-on-write filesystems (ZFS, Btrfs) and SSDs with wear leveling, which is why decrypting to a RAM-backed filesystem is the safer option.

## Export directly to removable media

Write the backup file to a USB drive, then physically disconnect it:

```
sk2 export -o /mnt/usb/sk2-export.sk2backup      # Linux/macOS
sk2 export -o E:\sk2-export.sk2backup             # Windows
```

## Verify the backup

After exporting, confirm you can restore it before relying on it. For SK2B, do a dry run against a throwaway vault:

```
SK2_VAULT=/tmp/verify.db sk2 init
SK2_VAULT=/tmp/verify.db sk2 import sk2-export.sk2backup
rm /tmp/verify.db
```

For GPG:

```
gpg -d sk2-export.csv.gpg | head -2               # Linux/macOS
```

```
gpg -d sk2-export.csv.gpg | Select-Object -First 2   # Windows (PowerShell)
```

## Use a different passphrase

Whether you pick SK2B or GPG, the backup passphrase is independent of your vault master password. Don't reuse them — if someone obtains both the vault file and the backup file, one password shouldn't unlock them both.
