# CookieBridge quick start

CookieBridge moves ordinary login cookies from Chrome to Vivaldi on the same
computer. It does not upload anything.

## 1. Load the extension in both browsers

1. Download or clone this repository and keep the folder until you finish.
2. In Chrome, open `chrome://extensions`.
3. Enable **Developer mode**, choose **Load unpacked**, and select the folder
   containing `manifest.json`.
4. In Vivaldi, open `vivaldi://extensions` and repeat the same steps with the
   same folder.

## 2. Export from Chrome

1. Open **Local Cookie Bridge** from Chrome's extension menu.
2. Leave **Selected domains** enabled and enter the sites you want to move,
   such as `example.com`, one per line. A full-profile export is available but
   contains every accessible login cookie.
3. Enter a passphrase of at least 12 characters. Keep it nearby; it cannot be
   recovered.
4. Choose **Create encrypted bundle** and approve Chrome's host-access prompt.
5. Review the cookie/domain count, tick the confirmation box, and choose
   **Create encrypted bundle** again.
6. Chrome saves an encrypted `.vcookies` file.

## 3. Import into Vivaldi

1. Open **Local Cookie Bridge** from Vivaldi's extension menu.
2. Select the `.vcookies` file and enter the same passphrase.
3. Keep **Preserve** selected unless you deliberately want Chrome's cookies to
   replace matching Vivaldi cookies.
4. Choose **Decrypt and inspect**, approve Vivaldi's host-access prompt, and
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
