# BD-JB-Relapse

A **BD-J** (Blu-ray Disc Java) port of the **relapse** PS5 kernel exploit, loaded
through **BD-JB5**. It gains kernel read/write and launches an ELF loader on the
console entirely from Java running inside the Disc Player's BD-J VM — no WebKit entry
point required.

**Status:** work in progress, but functional — it leaks the kernel base, gains kernel
R/W, escalates privileges (uid 0, out of the sandbox) and starts the elfldr payload
server.

> BD-J port by **EchoStretch, zecoxao and Claude**, with the close-panic teardown
> **fixed by 0xXOR**.
> Original *relapse* exploit from the PS5 research community (WebKit PoC).

**Version:** 2.1.0

## Supported firmware

PS5 firmwares up to and including **13.42**. Per-firmware offset tables are included
for **7.00 – 13.60** (`RelapseOffsets.java`); development and testing were done on a
13.42 devkit. 11.40 is included as well: upstream Relapse-Exploit skips it (the
firmware image is missing the modules its offsets are read from), so its table comes
from notmaj0r's relapse port.

## How it works

Relapse abuses the `aio_multi_wait` **mode-0 waiter use-after-free** (syscall `663` /
`0x297` with `mode = 0`). The dangling waiter is reclaimed to corrupt a `sysctl` OID,
yielding a slow kernel read/write primitive that is then upgraded to a fast
pipe-based R/W. After privilege escalation it hands control to an embedded loader
chain:

- **kexp** (ufm42) — applies the kernel patches and bootstraps the payload loader.
- **elfldr** (ps5-payload-dev) — migrates out to a system service and serves ELF
  payloads on **port 9021**.
- **unified autoloader** ([ps5-bdjb-autoloader](https://github.com/itsPLK/ps5-bdjb-autoloader))
  — streamed to elfldr as soon as the loader accepts connections. It kills the
  disc player entry point, then launches the payloads listed in
  `ps5_autoloader/autoload.txt` from USB or `/data`, or starts Payload Manager
  when no config exists. See [Autoloading payloads](#autoloading-payloads).

## Implementation notes (BD-J port)

Porting the original WebKit/JavaScript exploit to the BD-J VM required working around
several platform constraints on recent firmware:

- **Execute-only `libkernel` `.text`.** Code pages can't be read, so stub scanning
  and ROP gadget hunting are impossible — syscalls are reached through exported
  `libkernel` wrappers instead.
- **The UAF needs `mode = 0`, which the wrappers reject.** `sceKernelAioWaitRequests`
  validates its arguments and refuses `mode = 0` (`EINVAL`), but that mode is exactly
  what triggers the waiter UAF. The raw syscall stubs are not exported, yet they
  physically exist inside **`libkernel_sys`**; the port locates them at runtime by
  computing fixed offsets from a `dlsym`'d anchor and calls them directly with
  `mode = 0`.
- **No generic `syscall()` and no writable JIT before escalation.** `pipe2` is rebuilt
  from `pipe()` + `fcntl`, and the KASLR source address is obtained via `connect()` +
  `getsockname` rather than the (unreachable) interface-list APIs.
- **Clean teardown.** After launching the payload server the exploit gives every
  crossed pipe back its own buffer and size (saved before the crossing) and
  empties them, verifying each field through the slow window, so the eventual
  `pipe_free_kmem()` unmaps the real allocation at process exit. The hijacked
  `sysctl` OIDs cannot close the window that repairs them, so they are
  deliberately left modified until the next boot.

## Building

The project builds a single payload jar (`Relapse.jar`). You need:

- **JDK 8** (`javac` / `jar`) — the sources target `-source 1.4 -target 1.4`, which
  newer JDKs no longer support.
- A checkout of [john-tornblom/bdj-sdk](https://github.com/john-tornblom/bdj-sdk),
  which ships `enhanced-stubs.zip` and builds `sony-stubs.jar` (`make -C
  bdj-sdk/target`) under `target/lib/`. These are the same open stubs the `ps5-*`
  samples compile against — no proprietary firmware jars are required.

With the SDK built (`sony-stubs.jar` present under `bdj-sdk/target/lib/`):

```sh
make BDJSDK_HOME=/path/to/bdj-sdk JAVA8_HOME=/path/to/jdk8
```

Or compile directly with a JDK 8 and the two stub archives in one folder:

```sh
javac -Xlint:-options -source 1.4 -target 1.4 \
  -cp "enhanced-stubs.zip:sony-stubs.jar" \
  src/org/bdj/api/*.java src/org/bdj/*.java src/org/bdj/external/*.java
jar cfm Relapse.jar manifest.txt -C src/ .
```

(On Windows, use `;` instead of `:` in the classpath.) To build against a real
firmware `bdjstack.jar` + `rt.jar` instead, pass `CLASSPATH=...` to `make`.

Tagged pushes are built automatically by GitHub Actions
(`.github/workflows/release.yml`): the workflow provisions JDK 8 and the bdj-sdk
stubs, builds `Relapse.jar`, then assembles a bootable disc image from
[Gezine/BD-JB5](https://github.com/Gezine/BD-JB5) with `Relapse.jar` bundled as
the on-disc payload, and attaches both `Relapse.jar` and `BD-JB-Relapse-<tag>.iso`
to the matching GitHub release.

The embedded payloads under `src/org/bdj/external/` — kexp, elfldr and the
unified autoloader — are bundled into the jar automatically. The ISO also carries
`/ps5-unified-autoloader.elf` at the disc root, mirroring the upstream
autoloader disc layout.

## Usage

Each release ships two artifacts:

- **`BD-JB-Relapse-<version>.iso`** — a bootable BD-RE disc built from BD-JB5 2.0
  with `Relapse.jar` bundled on the disc as `payload.jar`. Burn it to BD-RE (or
  serve it however you normally run a BD-J disc) and insert it in the Disc Player.
  BD-JB5 escapes the BD-J sandbox and its `InternalJarLoader` auto-runs the bundled
  jar from `/disc/payload.jar` — **no network push needed.** This is the easiest
  way to run Relapse.
- **`Relapse.jar`** — the payload on its own, for the classic flow: load it with
  BD-JB5's **RemoteJarLoader** (`jar_client.py`, port **9025**).

Either way, once the exploit finishes the ELF loader listens on **port 9021**.
Relapse immediately hands that port to the autoloader, so payloads can be loaded
two ways:

- **Automatically** — put them in a `ps5_autoloader` directory with an
  `autoload.txt` (see below). This is what the bundled autoloader consumes.
- **Manually** — send an ELF to port 9021 yourself, exactly as before. elfldr
  keeps listening after the autoloader is done, so this still works.

Progress is reported over the on-console UDP logger (BD-JB5's RemoteLogger, port
**18194**; run its `log_client.py` first).

## Autoloading payloads

Once elfldr is up, Relapse streams the
[ps5-bdjb-autoloader](https://github.com/itsPLK/ps5-bdjb-autoloader) unified
autoloader into it. From then on the autoloader owns the boot:

1. it kills the disc player entry point (this app) — the exploit has already
   restored its pipes, so this is safe;
2. it looks for a config, in this order:
   - `/mnt/usb[0-7]/ps5_autoloader_bdjb/autoload.txt`
   - `/data/ps5_autoloader_bdjb/autoload.txt`
   - `/mnt/usb[0-7]/ps5_autoloader/autoload.txt`
   - `/data/ps5_autoloader/autoload.txt`
3. if found, it launches every listed payload through elfldr;
4. if not found, it starts the bundled **Payload Manager** so payloads can be
   configured from a browser.

To use the manual config, create `ps5_autoloader` on the root of a USB drive (or
`/data/ps5_autoloader` on the console) containing the `.elf`/`.bin` payloads and
an `autoload.txt`:

```text
# one entry per line; names are case-sensitive and relative to this directory
ftpsrv.elf
!1000                # sleep 1000 ms before the next entry
kstuff.elf
@sync                # optional: move this directory to /data after a clean run
```

`!<ms>` sleeps, `#` starts a comment, `@sync` copies the config to internal
storage once every payload loaded successfully. The `.elf` files in
`ps5_autoloader` are whatever you put there — the autoloader only bundles
Payload Manager as the no-config fallback.

## Payload versions

The chain shipped in `Relapse.jar` is:

| Payload | Version | Notes |
| --- | --- | --- |
| kexp | ufm42/kexp `0062384` (relinked 2026-10-26) | mapped as raw shellcode, entry at offset 0 |
| elfldr | ps5-payload-dev 0.27 build | loaded by kexp via `base + e_entry`; entry is `0x46b8` |
| unified autoloader | itsPLK/ps5-unified-autoloader `v0.1.7-abc3b82` | streamed to port 9021 |

`kexp` and `elfldr` are pinned to builds that match the loader ABI: kexp must be
relinked for offset-0 execution, and kexp loads elfldr with `base + e_entry` (the
upstream prebuilt release has `e_entry = 0`, so it is not a drop-in). Rebuild
those two from source and replace the blobs if you need newer code.

The autoloader has no such constraint and can be refreshed from its latest
release:

```sh
make payloads          # or: scripts/update_payloads.sh
make payload-versions  # show what is currently embedded
```

This downloads the newest `ps5-unified-autoloader-*.elf`, prunes the old one and
regenerates `PayloadPaths.java`, so the next `make` embeds it.


## Known issues

- Closing the application after running used to reboot the console: the crossed
  pipes were torn down with `pipe_buffer.buffer` still pointing at the peer
  `struct pipe`, so `pipe_free_kmem()` unmapped a UMA object as if it were the
  pipe's buffer. The teardown now writes both pipes' own buffers and sizes back,
  zeroes `count`/`in`/`out` and verifies every field by readback before returning.
  This is the fix measured on firmware 12.60 upstream, but it has not yet been
  validated on this port's 13.42 target; if a close still panics, reboot and
  re-run.
- The three hijacked `sysctl` OIDs remain modified until reboot. In particular
  `kern.smp.cpus` can return a kernel address instead of the CPU count. Nothing in
  the post-jailbreak chain has been observed to care.
- The `sysctl` write window cannot repair the pipes and restore its own OIDs in the
  same pass: the fast primitive overwrites the pipe field it repairs, and
  restoring the OIDs destroys the slow window. Repairing the pipes takes priority
  because their residue is what panics on close.

## Credits & acknowledgements

- **EchoStretch, zecoxao, Claude** — BD-J port.
- **0xXOR** — close-panic teardown fix (pipe buffer/size restore via the slow
  `sysctl` window).
- **relapse** — original PS5 kernel exploit (`aio_multi_wait` mode-0 UAF).
- **ufm42** — [kexp](https://github.com/ufm42/kexp).
- **ps5-payload-dev** — [elfldr](https://github.com/ps5-payload-dev/elfldr).
- **itsPLK** — [ps5-bdjb-autoloader](https://github.com/itsPLK/ps5-bdjb-autoloader)
  and [ps5-unified-autoloader](https://github.com/itsPLK/ps5-unified-autoloader).
- **notmaj0r** — Relapse offsets for firmware 11.40 (via
  [ps5-y2jb-autoloader](https://github.com/itsPLK/ps5-y2jb-autoloader)).
- **john-tornblom** — [bdj-sdk](https://github.com/john-tornblom/bdj-sdk).
- **Gezine** — BD-JB5 loader.
- **edisnord** — [relapse-y2jb](https://github.com/edisnord/relapse-y2jb): hardware
  analysis of the close panic and the pipe-restore method.
