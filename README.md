# ¿Qué ve Internet de esta IP?

[English](README.en.md)

Escribe una IP (v4 o v6) o un dominio y mira lo que Internet ya sabe de ella, **sin escanear nada**:

- **Puertos abiertos, software (CPE) y CVE conocidos** que Shodan ya registró, vía [InternetDB](https://internetdb.shodan.io/) (gratis y sin clave).
- **Red (ASN), titular y prefijo**, y país aproximado, vía [RIPEstat](https://stat.ripe.net/docs/data-api/).
- **Nombre inverso (PTR)** y resolución de dominios con el [DNS sobre HTTPS de Google](https://developers.google.com/speed/public-dns/docs/doh/json).

Por cada puerto explica en lenguaje claro qué servicio suele ser, qué riesgo implica y si conviene cerrarlo (base local de 42 puertos comunes). Los CVE enlazan a la herramienta hermana [¿Este CVE se está explotando ya?](https://ale0009.github.io/cve-explotado/).

> **Solo IPs propias o con permiso.** La página no envía ningún paquete a la IP consultada: lee datos públicos ya recolectados. Lo que escribes viaja a Shodan, RIPE NCC y Google.

## Cómo usarlo

- Abre `index.html` desde un servidor estático (`python3 -m http.server`) o en GitHub Pages. Arranca con el ejemplo `scanme.nmap.org`, el servidor que el proyecto Nmap ofrece para practicar.
- `?ip=scanme.nmap.org` abre directamente una consulta.
- `?sin-conexion` usa las respuestas reales guardadas el 10 nov 2026 en `datos/` (solo los ejemplos).
- Pruebas: `node --test` (Node 20+). Volver a grabar los datos: `node scripts/capturar.mjs datos/ejemplo-AAAA-MM-DD.json 1.1.1.1 …`.

## De qué trabajo sale

De los laboratorios de Nmap y las notas de hacking ético de la carrera de Ingeniería de Sistemas. La página [`/proceso/`](proceso/) cuenta el reconocimiento activo frente al pasivo, qué hace Nmap frente a este enfoque, la Ley 1273 de 2009 (art. 269A), las cifras calculadas, la fe de erratas del trabajo de clase y las limitaciones (por ejemplo, los datos de Shodan pueden estar desactualizados y los CVE se cruzan por versión, sin comprobarse).

## Créditos

[Mario Puerta «ale0009»](https://github.com/ale0009) × [David Rincón «Kuronoma»](https://www.linkedin.com/in/davidalexanderrinconcorredorkuronoma/)

Licencia MIT.
