import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { leerIdb, leerPrefijo, leerGeo, leerDns, urlIdb, urlPrefijo, urlGeo, urlDns } from '../js/fuentes.js';

const M = JSON.parse(readFileSync(new URL('./muestras/respuestas-2026-11-10.json', import.meta.url))).respuestas;

test('InternetDB real: scanme.nmap.org tiene puertos, CPE y CVE', () => {
  const r = leerIdb(M[urlIdb('45.33.32.156')]);
  assert.equal(r.estado, 'ok');
  assert.deepEqual(r.puertos, [22, 80, 123, 9929]);
  assert.ok(r.cpes.includes('cpe:/a:openbsd:openssh:6.6.1p1'));
  assert.ok(r.vulns.length > 100);
  assert.ok(r.vulns.every((v) => /^CVE-\d{4}-\d+$/.test(v)));
});

test('InternetDB real: 404 significa que Shodan no tiene datos, no un error', () => {
  assert.deepEqual(leerIdb(M[urlIdb('1.2.3.4')]), { estado: 'vacio' });
  assert.equal(leerIdb({ status: 429, json: { detail: 'x' } }).estado, 'error');
});

test('RIPEstat prefix-overview real: ASN y titular', () => {
  const r = leerPrefijo(M[urlPrefijo('1.1.1.1')]);
  assert.equal(r.asn, 13335);
  assert.match(r.titular, /Cloudflare/i);
  assert.equal(r.prefijo, '1.1.1.0/24');
  assert.equal(leerPrefijo(M[urlPrefijo('1.2.3.4')]).estado, 'vacio');
});

test('RIPEstat geo real: país ISO o desconocido', () => {
  assert.equal(leerGeo(M[urlGeo('8.8.8.8')]).pais, 'US');
  assert.deepEqual(leerGeo(M[urlGeo('1.1.1.1')]), { estado: 'vacio', pais: null, ciudad: null });
  assert.equal(leerGeo({ status: 502, json: null }).estado, 'error');
});

test('DNS sobre HTTPS real: PTR y resolución de dominio', () => {
  assert.deepEqual(leerDns(M[urlDns('8.8.8.8.in-addr.arpa', 'PTR')], 'PTR').valores, ['dns.google']);
  assert.deepEqual(leerDns(M[urlDns('scanme.nmap.org', 'A')], 'A').valores, ['45.33.32.156']);
  const nx = leerDns(M[urlDns('4.3.2.1.in-addr.arpa', 'PTR')], 'PTR');
  assert.equal(nx.nxdominio, true);
  assert.equal(nx.estado, 'vacio');
});

test('DNS: sigue la cadena CNAME y separa los registros pedidos', () => {
  const json = { Status: 0, Answer: [{ type: 5, data: 'github.com.' }, { type: 1, data: '140.82.114.4' }] };
  assert.deepEqual(leerDns({ status: 200, json }, 'A'), { estado: 'ok', nxdominio: false, valores: ['140.82.114.4'], cadena: ['github.com'] });
  assert.equal(leerDns({ status: 200, json: { Status: 2 } }, 'A').estado, 'error');
});
