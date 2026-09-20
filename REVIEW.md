# Review and regression fixes — 0.1.1

The review covered argument parsing, filename restrictions, protected file identity,
locks and Windows sharing, output publication, verification, cancellation, password
handling, key generation/restoration, and authenticated stream parsing. The commands
and version-1 file formats remain unchanged.

## Fixed findings

1. **Late hard links could escape the in-place restriction on Windows.** An input
   was checked when opened, but its link count was not checked again at commit.
   A regression test added a link between these stages and reproduced the failure
   before the fix. Replacement now repeats the link/filesystem/alternate-stream
   checks immediately before publication. The test now passes and preserves both
   names. This narrows the race window; it does not make an owner-writable directory
   secure against a malicious process changing it during the final syscall.

2. **Ctrl-C could hang an idle Windows password/text prompt.** A real hidden-console
   test reproduced a prompt still waiting after a control event. Windows now reads
   console input records with a short cancellation wait, restores the original input
   mode on exit, and handles keyboard Ctrl-C explicitly. Tests cover cancellation,
   normal hidden Unicode input, backspace, line/word editing, empty input, mismatched
   passwords, and deterministic restoration. Linux retains its existing terminal
   password reader and still needs native execution.

3. **Protected-file identity errors were ignored.** Previously any failure to inspect
   a protected path was treated like absence. Only a genuine not-found error is now
   ignored. A Windows sharing-denial test verifies that an uninspectable protected
   file stops processing.

4. **Recovery metadata was synchronized without a read-back comparison.** `key.meta`
   now uses the same write-digest and read-back verification as other outputs, before
   it is published. This matters because the metadata is needed to regenerate a key.

5. **Read-only rejection happened late, and device-name filtering had a gap.**
   Windows read-only in-place inputs are now rejected before output work. Device
   names with spaces before their extension, such as `NUL .txt`, are rejected too.

## Evidence and limits

The updated build passed 64 Rust tests, 17 Windows console scenarios, formatting,
Clippy with warnings denied, a dependency advisory scan, and independent SHA3 and
libsodium checks. The Linux variants passed cross-target checks and a static Linux
binary was rebuilt, but it has not been executed on Linux.

Synthetic read/write failure tests and real Windows sharing failures are covered.
Sudden power loss, physical disk-full/device failures, and hostile final-syscall
filesystem races were not tested. This work is a code review and regression test
pass, not an independent cryptographic security audit.

The Windows prompt implementation follows Microsoft's documented
[console input record](https://learn.microsoft.com/en-us/windows/console/readconsoleinput)
and [console mode](https://learn.microsoft.com/en-us/windows/console/setconsolemode)
interfaces. Atomic publication uses
[FILE_RENAME_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_rename_info).
