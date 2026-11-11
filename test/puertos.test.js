import { test } from 'node:test';
import assert from 'node:assert/strict';
import { BASE, evaluarPuertos, leerCpe, softwareSuelto, veredicto, resumenBase, RIESGOS, ACCIONES } from '../js/puertos.js';

const PEDIDOS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 9200, 27017];

test('la base cubre los puertos pedidos y no repite números', () => {
  const nums = BASE.map((f) => f.puerto);
  assert.equal(new Set(nums).size, nums.length);
  for (const p of PEDIDOS) assert.ok(nums.includes(p), `falta el ${p}`);
  assert.ok(BASE.length >= 38 && BASE.length <= 45);
});

test('cada ficha tiene riesgo, acción y explicación válidos', () => {
  for (const f of BASE) {
    assert.ok(RIESGOS[f.riesgo] && f.riesgo !== 'desconocido', `${f.puerto}`);
    assert.ok(ACCIONES[f.accion] && f.accion !== 'revisar', `${f.puerto}`);
    assert.ok(f.porque.length > 40 && f.porque.length < 200, `${f.puerto}: ${f.porque.length}`);
  }
});

test('lee CPE 2.2 y 2.3', () => {
  assert.deepEqual(
    (({ proveedor, producto, version, tipo }) => ({ proveedor, producto, version, tipo }))(leerCpe('cpe:/a:apache:http_server:2.4.7')),
    { proveedor: 'apache', producto: 'http_server', version: '2.4.7', tipo: 'aplicación' },
  );
  assert.equal(leerCpe('cpe:2.3:o:canonical:ubuntu_linux:*:*:*:*:*:*:*:*').texto, 'canonical ubuntu linux');
  assert.equal(leerCpe('no es cpe'), null);
});

test('ordena por riesgo y pega el software al puerto que le corresponde (scanme.nmap.org)', () => {
  const cpes = ['cpe:/a:apache:http_server:2.4.7', 'cpe:/o:canonical:ubuntu_linux', 'cpe:/a:openbsd:openssh:6.6.1p1', 'cpe:/a:ntp:ntp:3'];
  const ev = evaluarPuertos([22, 80, 123, 9929], cpes);
  assert.deepEqual(ev.map((e) => e.puerto), [22, 123, 9929, 80]);
  assert.equal(ev.find((e) => e.puerto === 22).software[0].producto, 'openssh');
  assert.equal(ev.find((e) => e.puerto === 80).software[0].version, '2.4.7');
  assert.equal(ev.find((e) => e.puerto === 9929).accion, 'revisar');
  assert.deepEqual(softwareSuelto(ev, cpes).map((c) => c.producto), ['ubuntu_linux']);
});

test('veredicto: alto, medio, bajo, nada y error', () => {
  assert.equal(veredicto({ estadoIdb: 'ok', evaluados: evaluarPuertos([443, 3389]) }).nivel, 'alto');
  assert.equal(veredicto({ estadoIdb: 'ok', evaluados: evaluarPuertos([22, 443]) }).nivel, 'medio');
  assert.equal(veredicto({ estadoIdb: 'ok', evaluados: evaluarPuertos([80, 443]) }).nivel, 'bajo');
  assert.equal(veredicto({ estadoIdb: 'ok', evaluados: evaluarPuertos([80, 443]), nVulns: 3 }).nivel, 'medio');
  assert.equal(veredicto({ estadoIdb: 'vacio' }).nivel, 'nada');
  assert.equal(veredicto({ estadoIdb: 'error' }).nivel, 'error');
});

test('cuenta acciones del veredicto (1.1.1.1)', () => {
  const v = veredicto({ estadoIdb: 'ok', evaluados: evaluarPuertos([53, 69, 80, 443, 2082, 2083, 2087, 2095, 2096, 8443, 8880]) });
  assert.deepEqual(v.acciones, { cerrar: 1, restringir: 2, normal: 2, revisar: 6 });
  assert.equal(v.riesgos.alto, 1);
});

test('resumen de la base (cifra «calculada aquí» de /proceso/)', () => {
  const r = resumenBase();
  assert.equal(r.total, BASE.length);
  assert.equal(r.riesgos.alto + r.riesgos.medio + r.riesgos.bajo, r.total);
  assert.equal(r.riesgos.desconocido, 0);
  assert.ok(r.altoCerrar <= r.riesgos.alto);
  assert.equal(r.basesDatos, 6);
});
