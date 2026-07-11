# CookieBridge quick start

CookieBridge moves ordinary login cookies between two local Chromium-based
browser profiles (Chrome, Edge, Brave, Opera, Vivaldi, Arc, etc.) on the same
computer. It does not upload anything. Only Chrome → Vivaldi has been tested
end to end; other browser pairs may work but are unverified.

## 1. Load the extension in both browsers

1. Download or clone this repository and keep the folder until you finish.
2. In your source browser, open its extensions page (e.g. `chrome://extensions`,
   `edge://extensions`, `vivaldi://extensions`).
3. Enable **Developer mode**, choose **Load unpacked**, and select the folder
   containing `manifest.json`.
4. In your destination browser, open its extensions page and repeat the same
   steps with the same folder.

## 2. Export from your source browser

1. Open **Local Cookie Bridge** from your source browser's extension menu.
2. Leave **Selected domains** enabled and enter the sites you want to move,
   such as `example.com`, one per line. A full-profile export is available but
   contains every accessible login cookie.
3. Enter a passphrase of at least 12 characters. Keep it nearby; it cannot be
   recovered.
4. Choose **Create encrypted bundle** and approve the host-access prompt.
5. Review the cookie/domain count, tick the confirmation box, and choose
   **Create encrypted bundle** again.
6. The browser saves an encrypted `.vcookies` file.

## 3. Import into your destination browser

1. Open **Local Cookie Bridge** from your destination browser's extension menu.
2. Select the `.vcookies` file and enter the same passphrase.
3. Keep **Preserve** selected unless you deliberately want the source browser's
   cookies to replace matching destination cookies. Close destination-site tabs
   during import; preserve mode rechecks each cookie, but Chromium cannot make
   that recheck and write atomic.
4. Choose **Decrypt and inspect**, approve the host-access prompt, and
   review the dry-run counts.
5. Choose **Import inspected cookies**.
6. Reload the relevant websites and confirm that you are signed in.

## 4. Clean up

1. Delete the `.vcookies` file.
2. Remove **Local Cookie Bridge** from both browsers.

Treat the bundle like a temporary password vault: anyone with the file and
passphrase may be able to use the sessions inside it. Some sites will still ask
you to sign in again because passkeys, browser storage, and device-bound
sessions are not cookies and cannot be transferred by this extension.
