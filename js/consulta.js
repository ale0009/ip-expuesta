// Orquesta la consulta pasiva. No toca la IP: solo pregunta a bases públicas que ya la observaron.
// `pedir(url)` → Promise<{ status, json }>. Se inyecta para poder usar la red, el respaldo guardado o pruebas.
import { analizarEntrada, rangoNoPublico, nombrePtr } from './entrada.js';
import { urlIdb, urlPrefijo, urlGeo, urlDns, leerIdb, leerPrefijo, leerGeo, leerDns } from './fuentes.js';

const comoError = (e, quien) => ({ estado: 'error', detalle: `${quien}: ${e?.message ?? e}` });

async function leer(pedir, url, lector, quien, ...extra) {
  try {
    return lector(await pedir(url), ...extra);
  } catch (e) {
    return comoError(e, quien);
  }
}

/** Resuelve un dominio: primero IPv4 (A); si no tiene, IPv6 (AAAA). */
export async function resolver(dominio, pedir) {
  const a = await leer(pedir, urlDns(dominio, 'A'), leerDns, 'dns.google', 'A');
  if (a.estado === 'ok') return { ...a, tipo: 'ipv4' };
  if (a.estado === 'error' || a.nxdominio) return a;
  const aaaa = await leer(pedir, urlDns(dominio, 'AAAA'), leerDns, 'dns.google', 'AAAA');
  return aaaa.estado === 'ok' ? { ...aaaa, tipo: 'ipv6' } : aaaa;
}

/**
 * Texto → resultado:
 *   { tipo: 'entrada', mensaje } · { tipo: 'dns', dominio, mensaje } · { tipo: 'privada', ip, motivo }
 *   { tipo: 'ok', ip, familia, dominio, otrasIps, cadena, idb, red, geo, ptr }
 */
export async function consultar(texto, pedir) {
  const e = analizarEntrada(texto);
  if (e.tipo === 'vacia' || e.tipo === 'invalida') return { tipo: 'entrada', mensaje: e.mensaje, valor: e.valor };
  let ip = e.valor;
  let familia = e.tipo;
  let dominio = null;
  let otrasIps = [];
  let cadena = [];
  if (e.tipo === 'dominio') {
    dominio = e.valor;
    const r = await resolver(dominio, pedir);
    if (r.estado !== 'ok') {
      const mensaje = r.nxdominio ? `El dominio ${dominio} no existe en el DNS.`
        : r.estado === 'vacio' ? `${dominio} existe, pero no apunta a ninguna IP (no tiene registros A ni AAAA).`
          : `No pude resolver ${dominio}: ${r.detalle}.`;
      return { tipo: 'dns', dominio, mensaje, error: r.estado === 'error' };
    }
    [ip, ...otrasIps] = r.valores;
    familia = r.tipo;
    cadena = r.cadena;
  }
  const motivo = rangoNoPublico(familia, ip);
  if (motivo) return { tipo: 'privada', ip, familia, dominio, motivo };

  const [idb, red, geo, ptr] = await Promise.all([
    leer(pedir, urlIdb(ip), leerIdb, 'InternetDB'),
    leer(pedir, urlPrefijo(ip), leerPrefijo, 'RIPEstat'),
    leer(pedir, urlGeo(ip), leerGeo, 'RIPEstat (geo)'),
    leer(pedir, urlDns(nombrePtr(familia, ip), 'PTR'), leerDns, 'dns.google', 'PTR'),
  ]);
  return { tipo: 'ok', ip, familia, dominio, otrasIps, cadena, idb, red, geo, ptr };
}

/** Lista de URL que consultar() pediría para una IP pública ya validada (sirve para grabar el respaldo). */
export function urlsDeIp(familia, ip) {
  return [urlIdb(ip), urlPrefijo(ip), urlGeo(ip), urlDns(nombrePtr(familia, ip), 'PTR')];
}

/** pedir() con la red real: tiempo límite y errores claros. */
export function crearPedirVivo(fetchFn = globalThis.fetch, ms = 12000) {
  return async (url) => {
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), ms);
    try {
      const r = await fetchFn(url, { signal: ctl.signal, headers: { Accept: 'application/json' } });
      let json = null;
      try { json = await r.json(); } catch { /* cuerpo no JSON (p. ej., 502 de un proxy) */ }
      return { status: r.status, json };
    } catch (e) {
      throw new Error(e?.name === 'AbortError' ? `sin respuesta en ${ms / 1000} s` : 'no hubo conexión (red caída o bloqueada)');
    } finally {
      clearTimeout(t);
    }
  };
}

/** pedir() desde respuestas grabadas: { respuestas: { url: { status, json } } }. */
export function crearPedirGuardado(datos) {
  return async (url) => {
    const r = datos?.respuestas?.[url];
    if (!r) throw new Error('esta consulta no está entre los datos guardados');
    return r;
  };
}

/**
 * Red primero; si una URL falla por red o el servidor da 5xx, usa la respuesta guardada (si existe).
 * `usados` acumula las URL que salieron del respaldo, para avisarlo en pantalla.
 */
export function crearPedirConRespaldo(vivo, guardado) {
  const usados = new Set();
  const pedir = async (url) => {
    try {
      const r = await vivo(url);
      if (r.status < 500) return r;
      throw new Error(`HTTP ${r.status}`);
    } catch (e) {
      try {
        const r = await guardado(url);
        usados.add(url);
        return r;
      } catch {
        throw e;
      }
    }
  };
  pedir.usados = usados;
  return pedir;
}
