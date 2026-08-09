# Browser console

ECHO Vault includes a same-origin operator console at `/console`. It exists for operators who do not have autonomous tooling and covers the common human journeys: runtime status, namespace inventory, create, reveal, rotate, soft-delete, audit verification, and administrative rekeying.

## Security contract

- The console never asks the server for a browser session or cookie.
- The client signing secret is imported as a non-exportable Web Crypto HMAC key.
- Signing material is held only in JavaScript memory and clears on lock, navigation, or 15 minutes of inactivity.
- No credential, plaintext secret, namespace, or client ID is written to `localStorage`, `sessionStorage`, IndexedDB, service workers, cookies, URLs, or analytics.
- Every operation uses the same method/path/query/exact-body/timestamp/nonce HMAC contract as the CLI.
- Plaintext fields clear after write, update, dialog close, or automatic reveal timeout.
- Content Security Policy allows only same-origin static assets and connections. Frames, cameras, microphones, geolocation, payments, and cross-origin resources are disabled.

Remote use requires HTTPS because Web Crypto signing and Clipboard APIs are secure-context features. Loopback HTTP remains available for local development.

## Scope behavior

The GUI does not grant authority. A read-only client can list and reveal only permitted namespaces; write, delete, audit, and admin controls fail closed when the client lacks the corresponding scope. Use a separate, narrow client per operator role rather than sharing the bootstrap administrator.

## Accessibility and responsive behavior

The console uses semantic forms and tables, visible focus states, a skip link, status announcements, keyboard-operable dialogs, high-contrast colors, and reduced-motion support. The navigation collapses to a horizontal rail and the work area to one column on narrow screens.
