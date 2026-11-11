import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ordenarCves, porAnio, enlaceCve, enlaceLote, MAX_LOTE } from '../js/cves.js';
import { barrasAnios, barrasH } from '../js/graficas.js';

test('ordena CVE del más reciente al más antiguo y quita duplicados', () => {
  assert.deepEqual(ordenarCves(['CVE-2014-0098', 'cve-2024-38476', 'CVE-2024-38473', 'CVE-2014-0098']), ['CVE-2024-38476', 'CVE-2024-38473', 'CVE-2014-0098']);
});

test('cuenta por año y rellena los años sin CVE', () => {
  assert.deepEqual(porAnio(['CVE-2020-1', 'CVE-2022-2', 'CVE-2022-3']), [[2020, 1], [2021, 0], [2022, 2]]);
  assert.deepEqual(porAnio([]), []);
});

test('enlaces a la herramienta hermana (uno y en lote de 40)', () => {
  assert.equal(enlaceCve('CVE-2021-44228'), 'https://ale0009.github.io/cve-explotado/?cve=CVE-2021-44228');
  const ids = Array.from({ length: 55 }, (_, i) => `CVE-2020-${1000 + i}`);
  const l = enlaceLote(ids);
  assert.equal(l.n, MAX_LOTE);
  assert.equal(l.fuera, 15);
  assert.ok(l.url.includes('CVE-2020-1054,CVE-2020-1053'));
});

test('gráficas SVG: barras por año y horizontales', () => {
  const svg = barrasAnios([[2024, 2], [2025, 0], [2026, 5]]);
  assert.match(svg, /^<svg/);
  assert.equal((svg.match(/<rect/g) || []).length, 2);
  assert.equal((svg.match(/g-dest/g) || []).length, 1);
  assert.equal(barrasAnios([]), '');
  const h = barrasH([{ etiqueta: 'Alto <x>', valor: 25 }, { etiqueta: 'Bajo', valor: 7 }]);
  assert.match(h, /Alto &lt;x&gt;/);
});
