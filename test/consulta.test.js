import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { consultar, crearPedirGuardado, crearPedirConRespaldo, crearPedirVivo, urlsDeIp } from '../js/consulta.js';

const datos = JSON.parse(readFileSync(new URL('./muestras/respuestas-2026-11-10.json', import.meta.url)));
const guardado = crearPedirGuardado(datos);

test('dominio → IP → cuatro fuentes (scanme.nmap.org, datos reales)', async () => {
  const r = await consultar('scanme.nmap.org', guardado);
  assert.equal(r.tipo, 'ok');
  assert.equal(r.ip, '45.33.32.156');
  assert.equal(r.dominio, 'scanme.nmap.org');
  assert.equal(r.red.asn, 63949);
  assert.deepEqual(r.ptr.valores, ['scanme.nmap.org']);
  assert.deepEqual(r.idb.puertos, [22, 80, 123, 9929]);
});

test('IPv6 real (resolvedor de Cloudflare)', async () => {
  const r = await consultar('2606:4700:4700:0:0:0:0:1111', guardado);
  assert.equal(r.ip, '2606:4700:4700::1111');
  assert.equal(r.red.asn, 13335);
  assert.deepEqual(r.ptr.valores, ['one.one.one.one']);
});

test('IP privada: no se pregunta nada a nadie', async () => {
  let pedidos = 0;
  const r = await consultar('192.168.1.111', async () => { pedidos += 1; return { status: 200, json: {} }; });
  assert.equal(r.tipo, 'privada');
  assert.match(r.motivo, /laboratorio/);
  assert.equal(pedidos, 0);
});

test('entrada inválida y dominio inexistente', async () => {
  assert.equal((await consultar('999.1.1.1', guardado)).tipo, 'entrada');
  const nx = await consultar('no-existe.invalid', async () => ({ status: 200, json: { Status: 3 } }));
  assert.equal(nx.tipo, 'dns');
  assert.match(nx.mensaje, /no existe/);
});

test('si una fuente falla, las demás siguen', async () => {
  const pedir = async (url) => {
    if (url.includes('stat.ripe.net')) throw new Error('caída');
    return guardado(url);
  };
  const r = await consultar('8.8.8.8', pedir);
  assert.equal(r.tipo, 'ok');
  assert.equal(r.red.estado, 'error');
  assert.equal(r.geo.estado, 'error');
  assert.deepEqual(r.idb.puertos, [53, 443]);
});

test('respaldo por URL cuando la red cae o da 5xx', async () => {
  const vivo = async (url) => (url.includes('shodan') ? { status: 502, json: null } : Promise.reject(new Error('sin red')));
  const pedir = crearPedirConRespaldo(vivo, guardado);
  const r = await consultar('1.1.1.1', pedir);
  assert.equal(r.idb.puertos.length, 11);
  assert.equal(pedir.usados.size, 4);
  assert.deepEqual([...pedir.usados].sort(), urlsDeIp('ipv4', '1.1.1.1').sort());
});

test('pedir vivo: traduce el tiempo agotado y lee el JSON', async () => {
  const lento = (url, { signal }) => new Promise((_, rej) => signal.addEventListener('abort', () => rej(Object.assign(new Error('x'), { name: 'AbortError' }))));
  await assert.rejects(crearPedirVivo(lento, 20)('https://x'), /sin respuesta/);
  const ok = crearPedirVivo(async () => ({ status: 404, json: async () => ({ detail: 'No information available' }) }));
  assert.deepEqual(await ok('https://x'), { status: 404, json: { detail: 'No information available' } });
});
