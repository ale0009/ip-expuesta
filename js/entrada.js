// Lectura de lo que escribe la persona: IPv4, IPv6 o dominio (también acepta una URL pegada).
// Funciones puras: no consultan nada.

/** "8.8.8.8" → [8, 8, 8, 8] o null. Rechaza ceros a la izquierda ("010") por ambiguos (octal). */
export function octetos(ip) {
  const p = String(ip).split('.');
  if (p.length !== 4) return null;
  const n = p.map((x) => (/^(0|[1-9]\d{0,2})$/.test(x) ? Number(x) : NaN));
  return n.every((x) => x >= 0 && x <= 255) ? n : null;
}

/** IPv6 en cualquier forma abreviada → 8 grupos de 16 bits, o null. Admite IPv4 incrustada (::ffff:1.2.3.4). */
export function gruposIpv6(ip) {
  let s = String(ip).toLowerCase();
  if (!s.includes(':') || /[^0-9a-f:.]/.test(s)) return null;
  const v4 = s.match(/:(\d+\.\d+\.\d+\.\d+)$/);
  if (v4) {
    const o = octetos(v4[1]);
    if (!o) return null;
    s = `${s.slice(0, -v4[1].length)}${((o[0] << 8) | o[1]).toString(16)}:${((o[2] << 8) | o[3]).toString(16)}`;
  }
  const partes = s.split('::');
  if (partes.length > 2) return null;
  const leer = (t) => (t === '' ? [] : t.split(':'));
  const izq = leer(partes[0]);
  const der = partes.length === 2 ? leer(partes[1]) : [];
  if ([...izq, ...der].some((g) => !/^[0-9a-f]{1,4}$/.test(g))) return null;
  const faltan = 8 - izq.length - der.length;
  if (partes.length === 1 ? faltan !== 0 : faltan < 1) return null;
  return [...izq, ...Array(partes.length === 2 ? faltan : 0).fill('0'), ...der].map((g) => parseInt(g, 16));
}

/** 8 grupos → forma corta canónica (RFC 5952): minúsculas y el tramo de ceros más largo como "::". */
export function ipv6Corta(grupos) {
  let ini = -1; let largo = 0;
  for (let i = 0; i < 8; i += 1) {
    if (grupos[i] !== 0) continue;
    let j = i;
    while (j < 8 && grupos[j] === 0) j += 1;
    if (j - i > largo && j - i > 1) { ini = i; largo = j - i; }
    i = j;
  }
  const hex = grupos.map((g) => g.toString(16));
  if (ini < 0) return hex.join(':');
  return `${hex.slice(0, ini).join(':')}::${hex.slice(ini + largo).join(':')}`;
}

/** Nombre de dominio válido (ASCII, ya en punycode). Exige al menos un punto y un TLD que no sea solo números. */
export function esDominio(d) {
  if (!d || d.length > 253) return false;
  const et = d.split('.');
  if (et.length < 2) return false;
  if (!et.every((e) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(e))) return false;
  return /[a-z]/.test(et[et.length - 1]);
}

/**
 * Texto libre → { tipo: 'ipv4' | 'ipv6' | 'dominio' | 'vacia' | 'invalida', valor, mensaje? }.
 * Limpia espacios, esquema, ruta y puerto: "https://Ejemplo.com:8080/x" → dominio "ejemplo.com".
 */
export function analizarEntrada(texto) {
  let s = String(texto ?? '').trim();
  if (!s) return { tipo: 'vacia', valor: '', mensaje: 'Escribe una IP (como 1.1.1.1) o un dominio (como ejemplo.com).' };
  s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '').replace(/[/?#].*$/, '').replace(/^[^@]*@/, '');
  const corchetes = s.match(/^\[([^\]]+)\](?::\d+)?$/);
  if (corchetes) s = corchetes[1];
  const g6 = gruposIpv6(s);
  if (g6) return { tipo: 'ipv6', valor: ipv6Corta(g6) };
  s = s.replace(/:\d{1,5}$/, '').replace(/\.$/, '');
  if (/^[\d.]+$/.test(s)) {
    return octetos(s) ? { tipo: 'ipv4', valor: s }
      : { tipo: 'invalida', valor: s, mensaje: 'Eso parece una IPv4, pero no es válida: son cuatro números de 0 a 255 separados por puntos.' };
  }
  let host = s.toLowerCase();
  try { host = new URL(`http://${host}`).hostname; } catch { /* lo valida esDominio */ }
  if (esDominio(host)) return { tipo: 'dominio', valor: host };
  return { tipo: 'invalida', valor: s, mensaje: 'No reconozco eso como IP ni como dominio. Ejemplos: 1.1.1.1, 2606:4700:4700::1111, ejemplo.com.' };
}

// Rangos que Internet no enruta (o que son de documentación): si se escriben, no hay nada que preguntar.
const RANGOS_V4 = [
  ['0.0.0.0', 8, 'red «esta red» (0.0.0.0/8)'],
  ['10.0.0.0', 8, 'red privada (10.0.0.0/8, RFC 1918)'],
  ['100.64.0.0', 10, 'red compartida del operador (CGNAT, 100.64.0.0/10)'],
  ['127.0.0.0', 8, 'tu propio equipo (loopback, 127.0.0.0/8)'],
  ['169.254.0.0', 16, 'dirección de enlace local (169.254.0.0/16)'],
  ['172.16.0.0', 12, 'red privada (172.16.0.0/12, RFC 1918)'],
  ['192.0.0.0', 24, 'bloque reservado del IETF (192.0.0.0/24)'],
  ['192.0.2.0', 24, 'red de documentación (TEST-NET-1)'],
  ['192.168.0.0', 16, 'red privada (192.168.0.0/16, RFC 1918), como la de tu casa o la del laboratorio'],
  ['198.18.0.0', 15, 'red de pruebas de rendimiento (198.18.0.0/15)'],
  ['198.51.100.0', 24, 'red de documentación (TEST-NET-2)'],
  ['203.0.113.0', 24, 'red de documentación (TEST-NET-3)'],
  ['224.0.0.0', 4, 'dirección multicast (224.0.0.0/4)'],
  ['240.0.0.0', 4, 'bloque reservado (240.0.0.0/4)'],
];
const aEntero = (o) => ((o[0] << 24) >>> 0) + (o[1] << 16) + (o[2] << 8) + o[3];

/** Si la IP no es pública, devuelve por qué (texto); si es pública, null. */
export function rangoNoPublico(tipo, ip) {
  if (tipo === 'ipv4') {
    const n = aEntero(octetos(ip));
    for (const [base, bits, motivo] of RANGOS_V4) {
      const mascara = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
      if (((n & mascara) >>> 0) === aEntero(octetos(base))) return motivo;
    }
    return null;
  }
  if (tipo === 'ipv6') {
    const g = gruposIpv6(ip);
    if (g.every((x) => x === 0)) return 'dirección sin especificar (::)';
    if (g.slice(0, 7).every((x) => x === 0) && g[7] === 1) return 'tu propio equipo (loopback, ::1)';
    if ((g[0] & 0xfe00) === 0xfc00) return 'red privada IPv6 (ULA, fc00::/7)';
    if ((g[0] & 0xffc0) === 0xfe80) return 'dirección de enlace local (fe80::/10)';
    if ((g[0] & 0xff00) === 0xff00) return 'dirección multicast (ff00::/8)';
    if (g[0] === 0x2001 && g[1] === 0x0db8) return 'red de documentación (2001:db8::/32)';
    if (g.slice(0, 5).every((x) => x === 0) && g[5] === 0xffff) return 'IPv4 escrita como IPv6 (::ffff:0:0/96): escríbela como IPv4';
    return null;
  }
  return null;
}

/** Nombre para la consulta inversa (PTR): 1.2.3.4 → 4.3.2.1.in-addr.arpa; IPv6 → nibbles al revés + ip6.arpa. */
export function nombrePtr(tipo, ip) {
  if (tipo === 'ipv4') return `${octetos(ip).reverse().join('.')}.in-addr.arpa`;
  const hex = gruposIpv6(ip).map((g) => g.toString(16).padStart(4, '0')).join('');
  return `${[...hex].reverse().join('.')}.ip6.arpa`;
}
