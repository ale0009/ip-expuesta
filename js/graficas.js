// Gráficas SVG propias (funciones puras: devuelven texto SVG). Los colores salen de las clases del CSS.
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]);

/**
 * Barras verticales de CVE por año del identificador. serie = [[año, n], …].
 * Destaca en rojo los años >= `desde` (por defecto, los dos últimos de la serie).
 */
export function barrasAnios(serie = [], { ancho = 560, alto = 190, desde = null, titulo = 'CVE por año' } = {}) {
  if (!serie.length) return '';
  const m = { izq: 34, der: 8, arr: 18, aba: 26 };
  const max = Math.max(...serie.map(([, n]) => n), 1);
  const paso = (ancho - m.izq - m.der) / serie.length;
  const h = alto - m.arr - m.aba;
  const corte = desde ?? serie[Math.max(0, serie.length - 2)][0];
  const cada = serie.length > 14 ? (ancho < 420 ? 5 : 3) : 1;
  const partes = [];
  const marcas = max <= 4 ? [0, max] : [0, Math.round(max / 2), max];
  for (const v of marcas) {
    const y = m.arr + h - (v / max) * h;
    partes.push(`<line class="g-reji" x1="${m.izq}" x2="${ancho - m.der}" y1="${y.toFixed(1)}" y2="${y.toFixed(1)}"/><text class="g-eje" x="${m.izq - 5}" y="${(y + 4).toFixed(1)}" text-anchor="end">${v}</text>`);
  }
  serie.forEach(([anio, n], i) => {
    const bh = (n / max) * h;
    const x = m.izq + i * paso + paso * 0.14;
    const w = Math.max(2, paso * 0.72);
    const clase = anio >= corte ? 'g-barra g-dest' : 'g-barra';
    if (n) partes.push(`<rect class="${clase}" x="${x.toFixed(1)}" y="${(m.arr + h - bh).toFixed(1)}" width="${w.toFixed(1)}" height="${bh.toFixed(1)}"><title>${anio}: ${n} CVE</title></rect>`);
    if (i % cada === 0 || i === serie.length - 1) partes.push(`<text class="g-eje" x="${(x + w / 2).toFixed(1)}" y="${alto - 8}" text-anchor="middle">${String(anio).slice(cada > 1 ? 0 : 2).padStart(cada > 1 ? 4 : 2, '0')}</text>`);
  });
  partes.push(`<line class="g-base" x1="${m.izq}" x2="${ancho - m.der}" y1="${m.arr + h}" y2="${m.arr + h}"/>`);
  return `<svg class="grafica" viewBox="0 0 ${ancho} ${alto}" role="img" aria-label="${esc(titulo)}">${partes.join('')}</svg>`;
}

/**
 * Barras horizontales etiquetadas. filas = [{ etiqueta, valor, clase? }].
 * Devuelve SVG con el número al final de cada barra.
 */
export function barrasH(filas = [], { ancho = 520, alto_fila = 34, etiqueta = 150, titulo = '' } = {}) {
  if (!filas.length) return '';
  const max = Math.max(...filas.map((f) => f.valor), 1);
  const util = ancho - etiqueta - 46;
  const alto = filas.length * alto_fila + 6;
  const partes = filas.map((f, i) => {
    const y = 4 + i * alto_fila;
    const w = Math.max(f.valor ? 3 : 0, (f.valor / max) * util);
    return `<text class="g-rotulo" x="${etiqueta - 8}" y="${y + alto_fila / 2 + 4}" text-anchor="end">${esc(f.etiqueta)}</text>`
      + `<rect class="g-barra ${f.clase ?? ''}" x="${etiqueta}" y="${y + 5}" width="${w.toFixed(1)}" height="${alto_fila - 12}"/>`
      + `<text class="g-num tinta" x="${(etiqueta + w + 6).toFixed(1)}" y="${y + alto_fila / 2 + 4}">${f.valor}</text>`;
  });
  return `<svg class="grafica" viewBox="0 0 ${ancho} ${alto}" role="img" aria-label="${esc(titulo)}">${partes.join('')}</svg>`;
}
