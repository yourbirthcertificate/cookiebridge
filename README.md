# Local Cookie Bridge

Local Cookie Bridge is a one-shot, unpacked Manifest V3 extension for moving
ordinary cookies from one local Chromium profile to another. Its intended use
is a same-machine migration between any Chromium-based browsers — for example
Chrome, Edge, Brave, Opera, Vivaldi, or Arc.

**Want the short version?** Follow the [CookieBridge quick start](QUICKSTART.md).

The extension has no content scripts, remote code, analytics, telemetry, or
network calls. It reads and writes cookies only after an explicit button click
and a Chromium host-permission prompt. Exports are encrypted locally with
AES-256-GCM; the key is derived from a passphrase using PBKDF2-HMAC-SHA-256.

## Install in your source and destination browsers

Any Chromium-based browser works on either side — for example Chrome, Edge,
Brave, Opera, Vivaldi, or Arc — as long as it supports unpacked Manifest V3
extensions and its extensions page follows the usual `<scheme>://extensions`
pattern (e.g. `chrome://extensions`, `edge://extensions`, `vivaldi://extensions`).

1. Keep this folder in a stable local location until migration is complete.
2. In your source browser, open its extensions page, enable **Developer
   mode**, click **Load unpacked**, and select this repository folder.
3. In your destination browser, open its extensions page, enable **Developer
   mode**, click **Load unpacked**, and select the same folder.
4. Pin **Local Cookie Bridge** temporarily in each browser if desired.

## Migrate

1. Click the extension in the source browser profile.
2. Choose selected domains or explicitly confirm a full regular-profile export.
   Selected-domain mode shows its exact matched cookie/domain counts and requires
   a second confirmation, preventing accidental public-suffix-wide exports.
3. Generate or enter a passphrase and create the `.vcookies` bundle.
4. Click the extension in the destination browser profile.
5. Select the bundle, enter the passphrase, and click **Decrypt and inspect**.
6. Review the dry-run counts. Choose whether exact destination conflicts are
   preserved or overwritten.
7. Import. The extension writes cookies sequentially and then takes a fresh
   cookie snapshot to verify the result.
8. Reload destination tabs and check important sessions.
9. Delete the `.vcookies` file and remove the unpacked extension from both
   browsers.

Run the process separately for each source/destination browser profile.
Incognito stores are intentionally excluded.

## What is preserved

- name and value;
- domain and host-only behavior;
- path;
- Secure and HttpOnly;
- SameSite;
- session versus persistent lifetime;
- expiration, subject to Chromium's current maximum-lifetime clamp;
- partition key and cross-site-ancestor bit on browsers that support the
  current partitioned-cookie API.

The exporter uses Chromium's partition wildcard query, which includes both
unpartitioned and partitioned cookies. Import is sequential because cookie
creation order can affect path ordering, quota eviction, and Secure-cookie
overlay rules.

## Known boundaries

This is cookie migration, not a complete browser-session clone. It does not
move localStorage, IndexedDB, service workers, passkeys, client certificates,
TLS state, or device-bound session keys. Sites using Chrome Device-Bound
Session Credentials can require a fresh login even when their cookie was
successfully recreated.

Chromium 148+ (the engine underlying Chrome, Edge, Brave, Opera, Vivaldi, and
similar browsers) can bind cookies to their source scheme and, for host-only
cookies, their source port. The extension cookie API does not expose those fields.
Secure cookies therefore use their determinate HTTPS scheme and a default-port
reconstruction; a non-default hidden source port remains an edge case.
Non-Secure cookies use an HTTPS/default-port heuristic and are counted in the
inspection report. Source or destination duplicate records that may differ only by hidden
origin-binding fields are marked non-portable rather than silently collapsed.
Non-default-port applications are the main expected edge case.

The API also omits original creation/access timestamps and priority. Imported
cookies receive new creation timestamps and browser-default priority. A newer
public-suffix list can reject an older domain, and persistent expirations over
Chromium's limit can be shortened; both appear in the verification report.
Chromium cookie quotas can also evict existing destination cookies when new
ones are added. The verifier compares pre/post identity multisets and reports
any pre-existing identities that disappear, though concurrent site activity can
produce the same warning because the cookie API has no transactional snapshot.
There is also no batch transaction or rollback API. If a browser-level failure
occurs after some writes, the UI reports the partial-write count explicitly.

## Security model

- No source file contains `fetch`, XMLHttpRequest, WebSocket, EventSource, or
  beacon code. `npm run validate` checks this invariant.
- The extension CSP blocks network connections, frames, forms, remote scripts,
  and media at runtime in addition to the static no-network check.
- Broad optional host access persists until the unpacked extension is removed.
  This avoids one extension tab revoking another tab's access during a partial
  import; remove the extension immediately after migration.
- The action reuses its existing app tab, and a browser-wide Web Lock serializes
  operations if the page is duplicated manually.
- No cookie value is written to status text, reports, logs, extension storage,
  or the cleartext bundle envelope.
- The AES-GCM authentication tag makes tampering fail before import.
- Import inspection is read-only. Cookie writes require a separate explicit
  click.
- Existing destination cookies are preserved by default.
- Expired input is skipped before `cookies.set`; setting an expired cookie
  could otherwise delete its destination equivalent.
- Decrypted values are held in page memory only and references are cleared
  after import or when the page closes.

The encrypted bundle is still sensitive. A weak passphrase can be guessed, and
valid session cookies can grant account access. Delete it promptly.

## Development checks

No package installation is required.

```
npm run check
```

The tests cover encryption integrity, domain filtering, exact cookie identity,
host-only/domain behavior, prefixes, partitions, conflict modes, expired-cookie
safety, duplicate origin bindings, and post-import expiration verification.
