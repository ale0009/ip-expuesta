// CVE que InternetDB asocia a la IP (por la versión del software que anuncia, no porque se haya probado).
export const URL_HERMANA = 'https://ale0009.github.io/cve-explotado/';
export const MAX_LOTE = 40; // la herramienta hermana consulta hasta 40 CVE a la vez

const partes = (id) => id.match(/^CVE-(\d{4})-(\d+)$/i)?.slice(1).map(Number) ?? [0, 0];

/** Ordena del más reciente al más antiguo (año y número). */
export function ordenarCves(ids = []) {
  return [...new Set(ids.map((x) => x.toUpperCase()))].sort((a, b) => {
    const [ya, na] = partes(a);
    const [yb, nb] = partes(b);
    return yb - ya || nb - na;
  });
}

/** Cuenta por año de publicación del identificador → [[año, n], …] ascendente, rellenando años vacíos. */
export function porAnio(ids = []) {
  const c = new Map();
  for (const id of ids) {
    const [y] = partes(id);
    if (y) c.set(y, (c.get(y) ?? 0) + 1);
  }
  if (!c.size) return [];
  const anios = [...c.keys()];
  const res = [];
  for (let y = Math.min(...anios); y <= Math.max(...anios); y += 1) res.push([y, c.get(y) ?? 0]);
  return res;
}

export const enlaceCve = (id) => `${URL_HERMANA}?cve=${encodeURIComponent(id)}`;

/** Enlace con los más recientes (hasta 40) para priorizarlos en la herramienta hermana. */
export function enlaceLote(ids = []) {
  const todos = ordenarCves(ids);
  const lote = todos.slice(0, MAX_LOTE);
  return { url: `${URL_HERMANA}?cve=${lote.join(',')}`, n: lote.length, fuera: todos.length - lote.length };
}
