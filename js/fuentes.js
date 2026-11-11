// Fuentes públicas, todas sin clave y con CORS abierto (verificado con curl el 10 nov 2026):
//   InternetDB (Shodan) · puertos vistos, CPE y CVE por versión  → https://internetdb.shodan.io/<ip>
//   RIPEstat            · ASN, titular y prefijo anunciado; país aproximado (MaxMind GeoLite)
//   dns.google (DoH)    · nombre inverso (PTR) y resolución de dominios (A / AAAA)
// Funciones puras: reciben { status, json } ya descargado.

export const URL_IDB = 'https://internetdb.shodan.io/';
export const URL_RIPE = 'https://stat.ripe.net/data/';
export const URL_DOH = 'https://dns.google/resolve';
const APP = 'sourceapp=ip-expuesta';

export const urlIdb = (ip) => `${URL_IDB}${ip}`;
export const urlPrefijo = (ip) => `${URL_RIPE}prefix-overview/data.json?resource=${encodeURIComponent(ip)}&${APP}`;
export const urlGeo = (ip) => `${URL_RIPE}maxmind-geo-lite/data.json?resource=${encodeURIComponent(ip)}&${APP}`;
export const urlDns = (nombre, tipo) => `${URL_DOH}?name=${encodeURIComponent(nombre)}&type=${tipo}`;

const TIPO_DNS = { A: 1, CNAME: 5, PTR: 12, AAAA: 28 };
const sinPunto = (s) => String(s).replace(/\.$/, '');

/** InternetDB: 200 → datos; 404 → 'vacio' (Shodan no tiene nada de esa IP); otro → 'error'. */
export function leerIdb({ status, json }) {
  if (status === 404) return { estado: 'vacio' };
  if (status !== 200 || !json || !Array.isArray(json.ports)) return { estado: 'error', detalle: `InternetDB respondió ${status}` };
  const ordenar = (xs) => [...new Set(xs ?? [])].sort();
  return {
    estado: 'ok',
    ip: json.ip,
    puertos: [...new Set(json.ports)].sort((a, b) => a - b),
    cpes: ordenar(json.cpes),
    nombres: ordenar(json.hostnames),
    etiquetas: ordenar(json.tags),
    vulns: ordenar(json.vulns).filter((v) => /^CVE-\d{4}-\d{4,}$/i.test(v)).map((v) => v.toUpperCase()),
  };
}

/** RIPEstat prefix-overview → { estado, asn, titular, prefijo, anunciado, bloque }. */
export function leerPrefijo({ status, json }) {
  const d = json?.data;
  if (status !== 200 || !d) return { estado: 'error', detalle: `RIPEstat respondió ${status}` };
  const a = d.asns?.[0];
  return {
    estado: a ? 'ok' : 'vacio',
    asn: a?.asn ?? null,
    titular: a?.holder ?? null,
    otrosAsn: (d.asns ?? []).slice(1).map((x) => x.asn),
    prefijo: d.resource ?? null,
    anunciado: Boolean(d.announced),
    bloque: d.block?.desc ?? null,
  };
}

/** RIPEstat maxmind-geo-lite → { estado, pais (ISO-2), ciudad }. "?" o vacío = desconocido. */
export function leerGeo({ status, json }) {
  if (status !== 200 || !json?.data) return { estado: 'error', detalle: `RIPEstat (geo) respondió ${status}` };
  const loc = json.data.located_resources?.[0]?.locations?.[0];
  const pais = loc?.country && /^[A-Z]{2}$/.test(loc.country) ? loc.country : null;
  return { estado: pais ? 'ok' : 'vacio', pais, ciudad: loc?.city || null };
}

/** Respuesta DoH (JSON de dns.google) → { estado, valores, cadena (CNAME), nxdominio }. */
export function leerDns({ status, json }, tipo) {
  if (status !== 200 || !json || typeof json.Status !== 'number') return { estado: 'error', detalle: `dns.google respondió ${status}`, valores: [], cadena: [] };
  if (json.Status === 3) return { estado: 'vacio', nxdominio: true, valores: [], cadena: [] };
  if (json.Status !== 0) return { estado: 'error', detalle: `el DNS devolvió el código ${json.Status}`, valores: [], cadena: [] };
  const resp = json.Answer ?? [];
  const valores = resp.filter((r) => r.type === TIPO_DNS[tipo]).map((r) => sinPunto(r.data));
  const cadena = resp.filter((r) => r.type === TIPO_DNS.CNAME).map((r) => sinPunto(r.data));
  return { estado: valores.length ? 'ok' : 'vacio', nxdominio: false, valores, cadena };
}
