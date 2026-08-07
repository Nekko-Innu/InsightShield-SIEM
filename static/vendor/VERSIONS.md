# Vendored third-party assets

This directory holds the browser assets the app serves. They used to be loaded
from a CDN with an `onerror` handler falling back to these copies; the
templates now load these copies directly and never talk to a CDN. That closes
the supply-chain path into an admin console (jsdelivr and the Tailwind Play CDN
could each serve arbitrary script) and lets the nginx CSP drop both hosts.

**See** `reports/snoopy-brewing-widget.md` §4 for the re-download procedure and
§7.3 for how to verify these hashes match the files on disk. The §2 fallback
mechanism it describes no longer exists.

## Manifest

| File | Origin | Version | Size | SHA-256 |
| --- | --- | --- | --- | --- |
| `tailwindcss-3.4.3.min.js` | https://cdn.tailwindcss.com/3.4.3                                          | 3.4.3  | 410 707 | `0cf16cbf40af80098e59fd3b7b2d952ad9d8f5a6afa3982df68911e2a4976648` |
| `prism-1.29.0.min.css`     | https://cdn.jsdelivr.net/npm/prismjs@1.29.0/themes/prism.min.css           | 1.29.0 |   1 789 | `928e23e6b9fcef82c5f1d1f05b6f7fc5a6e187c60195e59fbf16fc9d071ee057` |
| `prism-tomorrow-1.29.0.min.css` | https://cdn.jsdelivr.net/npm/prismjs@1.29.0/themes/prism-tomorrow.min.css | 1.29.0 |   1 313 | `1b15fe2971998a048aebb60f26f6eed76122071db9ef3b995abd003224f52a98` |
| `prism-1.29.0.min.js`      | https://cdn.jsdelivr.net/npm/prismjs@1.29.0/prism.min.js                   | 1.29.0 |  19 644 | `11d136a060e78db4a558573a4fdc1a282c89f014c79de9221334d8c971707d0d` |
| `prism-json-1.29.0.min.js` | https://cdn.jsdelivr.net/npm/prismjs@1.29.0/components/prism-json.min.js   | 1.29.0 |     449 | `956d86baa5ae7ec4106758f354ac2d140bdcd7fc103dece02f73ed12b8d663e4` |

- **Downloaded:** 2026-04-24; `prism-tomorrow-1.29.0.min.css` added 2026-08-02
  when the CDN tags came out (it was the theme jsdelivr had been serving to
  `alert_detail.html` and `report.html`, and the light `prism.min.css` fallback
  would have rendered light tokens on their dark `<pre>` background).
- **Total footprint:** ~433 KB on disk, served on every page load.

## Verifying hashes

From this directory:

```bash
sha256sum *.js *.css
```

Each line must match the hash column above. Mismatch means the file was tampered
with or the CDN served a different payload; re-download per the procedure in the
plan file linked above.

## Licensing

- Tailwind CSS — MIT (<https://github.com/tailwindlabs/tailwindcss/blob/master/LICENSE>)
- Prism.js     — MIT (<https://github.com/PrismJS/prism/blob/master/LICENSE>)

Both licenses permit redistribution with attribution. Full license texts remain
upstream; this directory does not re-host them because the templates include
copyright notices via the upstream-minified files themselves.
