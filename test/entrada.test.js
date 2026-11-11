import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analizarEntrada, gruposIpv6, ipv6Corta, rangoNoPublico, nombrePtr, octetos } from '../js/entrada.js';

test('IPv4 válida y con ceros a la izquierda rechazados', () => {
  assert.deepEqual(analizarEntrada(' 1.1.1.1 '), { tipo: 'ipv4', valor: '1.1.1.1' });
  assert.equal(analizarEntrada('256.1.1.1').tipo, 'invalida');
  assert.equal(analizarEntrada('1.1.1').tipo, 'invalida');
  assert.equal(octetos('010.0.0.1'), null);
});

test('limpia URL, puerto y mayúsculas de un dominio', () => {
  assert.deepEqual(analizarEntrada('https://ScanMe.Nmap.org:8080/ruta?x=1'), { tipo: 'dominio', valor: 'scanme.nmap.org' });
  assert.deepEqual(analizarEntrada('1.1.1.1:53'), { tipo: 'ipv4', valor: '1.1.1.1' });
  assert.deepEqual(analizarEntrada('ejemplo.com.'), { tipo: 'dominio', valor: 'ejemplo.com' });
});

test('dominios con tildes pasan a punycode; palabras sueltas no son dominios', () => {
  assert.deepEqual(analizarEntrada('pañales.co'), { tipo: 'dominio', valor: 'xn--paales-xwa.co' });
  assert.equal(analizarEntrada('localhost').tipo, 'invalida');
  assert.equal(analizarEntrada('hola mundo').tipo, 'invalida');
  assert.equal(analizarEntrada('').tipo, 'vacia');
});

test('IPv6: expansión y forma corta canónica (RFC 5952)', () => {
  assert.deepEqual(gruposIpv6('2606:4700:4700::1111'), [0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111]);
  assert.equal(ipv6Corta(gruposIpv6('2001:0DB8:0:0:1:0:0:1')), '2001:db8::1:0:0:1');
  assert.deepEqual(analizarEntrada('[2001:4860:4860:0:0:0:0:8888]:443'), { tipo: 'ipv6', valor: '2001:4860:4860::8888' });
  assert.equal(gruposIpv6('1::2::3'), null);
  assert.equal(gruposIpv6('::ffff:1.2.3.4')[7], 0x0304);
});

test('rangos privados y de documentación no se consultan', () => {
  assert.match(rangoNoPublico('ipv4', '192.168.1.10'), /privada/);
  assert.match(rangoNoPublico('ipv4', '10.20.30.40'), /privada/);
  assert.match(rangoNoPublico('ipv4', '172.31.255.1'), /privada/);
  assert.equal(rangoNoPublico('ipv4', '172.32.0.1'), null);
  assert.match(rangoNoPublico('ipv4', '100.100.1.1'), /CGNAT/);
  assert.match(rangoNoPublico('ipv4', '203.0.113.9'), /documentación/);
  assert.match(rangoNoPublico('ipv4', '255.255.255.255'), /reservado/);
  assert.equal(rangoNoPublico('ipv4', '1.1.1.1'), null);
});

test('rangos IPv6 no públicos', () => {
  assert.match(rangoNoPublico('ipv6', '::1'), /loopback/);
  assert.match(rangoNoPublico('ipv6', 'fe80::1'), /enlace local/);
  assert.match(rangoNoPublico('ipv6', 'fd12:3456::1'), /ULA/);
  assert.match(rangoNoPublico('ipv6', '2001:db8::5'), /documentación/);
  assert.equal(rangoNoPublico('ipv6', '2606:4700:4700::1111'), null);
});

test('nombre para la consulta inversa PTR', () => {
  assert.equal(nombrePtr('ipv4', '45.33.32.156'), '156.32.33.45.in-addr.arpa');
  assert.equal(nombrePtr('ipv6', '2606:4700:4700::1111'), '1.1.1.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.7.4.0.0.7.4.6.0.6.2.ip6.arpa');
});
