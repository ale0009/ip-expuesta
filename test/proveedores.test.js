import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { proveedorPublico } from '../js/proveedores.js';
import { leerPrefijo, urlPrefijo } from '../js/fuentes.js';

const M = JSON.parse(readFileSync(new URL('./muestras/respuestas-2026-11-10.json', import.meta.url))).respuestas;

test('reconoce resolvedores públicos y no marca un servidor de cliente (scanme.nmap.org)', () => {
  assert.equal(proveedorPublico(leerPrefijo(M[urlPrefijo('1.1.1.1')])), 'Cloudflare');
  assert.equal(proveedorPublico(leerPrefijo(M[urlPrefijo('8.8.8.8')])), 'Google');
  assert.equal(proveedorPublico(leerPrefijo(M[urlPrefijo('9.9.9.9')])), 'Quad9');
  assert.equal(proveedorPublico(leerPrefijo(M[urlPrefijo('45.33.32.156')])), null);
  assert.equal(proveedorPublico({ estado: 'error' }), null);
});
