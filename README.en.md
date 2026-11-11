# What does the Internet see of this IP?

[Español](README.md)

Type an IP (v4 or v6) or a domain and see what the Internet already knows about it, **without scanning anything**:

- **Open ports, software (CPE) and known CVEs** already recorded by Shodan, via [InternetDB](https://internetdb.shodan.io/) (free, no key).
- **Network (ASN), holder and prefix**, plus approximate country, via [RIPEstat](https://stat.ripe.net/docs/data-api/).
- **Reverse name (PTR)** and domain resolution with [Google's DNS over HTTPS](https://developers.google.com/speed/public-dns/docs/doh/json).

For each port it explains in plain language (Spanish UI) which service it usually is, what risk it carries and whether you should close it (local base of 42 common ports). CVEs link to the sibling tool [Is this CVE being exploited yet?](https://ale0009.github.io/cve-explotado/).

> **Only your own IPs or with permission.** The page sends no packet to the queried IP: it reads public data that was already collected. What you type is sent to Shodan, RIPE NCC and Google.

## How to use

- Serve the folder statically (`python3 -m http.server`) or via GitHub Pages. It opens with the `scanme.nmap.org` example, the server the Nmap project offers for practice.
- `?ip=scanme.nmap.org` opens a query directly.
- `?sin-conexion` uses the real responses saved on 10 Nov 2026 in `datos/` (examples only).
- Tests: `node --test` (Node 20+). Re-record data: `node scripts/capturar.mjs datos/ejemplo-YYYY-MM-DD.json 1.1.1.1 …`.

## Where it comes from

From the Nmap labs and ethical hacking notes of a Systems Engineering degree. The [`/proceso/`](proceso/) page covers active vs. passive reconnaissance, Nmap vs. this approach, Colombian Law 1273 of 2009 (art. 269A), the figures computed here, an erratum of the class work and the limitations (Shodan data can be stale; CVEs are matched by version, not verified).

## Credits

[Mario Puerta «ale0009»](https://github.com/ale0009) × [David Rincón «Kuronoma»](https://www.linkedin.com/in/davidalexanderrinconcorredorkuronoma/)

MIT License.
