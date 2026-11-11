// Graba respuestas reales de InternetDB, RIPEstat y dns.google para el modo sin conexión y las pruebas.
// Uso: node scripts/capturar.mjs <salida.json> 1.1.1.1 scanme.nmap.org …
// Pasa cada consulta por consultar() con un pedir() que anota lo que responde la red.
import { writeFileSync } from 'node:fs';
import { consultar, crearPedirVivo } from '../js/consulta.js';

const [salida, ...entradas] = process.argv.slice(2);
if (!salida || !entradas.length) {
  console.error('Uso: node scripts/capturar.mjs <salida.json> <ip o dominio> …');
  process.exit(1);
}
const vivo = crearPedirVivo(fetch, 30000);
const respuestas = {};
const pedir = async (url) => {
  const r = await vivo(url);
  if (r.status >= 500) throw new Error(`${url} respondió ${r.status}`);
  const json = r.json && typeof r.json === 'object' ? { ...r.json } : r.json;
  // RIPEstat añade metadatos de su servidor que no hacen falta: se quitan para que el archivo pese menos.
  if (json?.data_call_name) for (const k of ['query_id', 'server_id', 'build_version', 'pipeline', 'process_time', 'cached', 'see_also']) delete json[k];
  respuestas[url] = { status: r.status, json };
  return { status: r.status, json };
};

for (const e of entradas) {
  const r = await consultar(e, pedir);
  console.log(`${e}: ${r.tipo} ${r.ip ?? ''} · puertos ${r.idb?.puertos?.join(',') ?? '–'} · CVE ${r.idb?.vulns?.length ?? 0} · AS${r.red?.asn ?? '?'} · ${r.geo?.pais ?? '?'} · PTR ${r.ptr?.valores?.[0] ?? '–'}`);
}
writeFileSync(salida, `${JSON.stringify({
  capturado: new Date().toISOString(),
  nota: 'Respuestas reales de InternetDB (Shodan), RIPEstat y dns.google, indexadas por URL. A RIPEstat se le quitaron metadatos del servidor.',
  entradas,
  respuestas,
}, null, 0)}\n`);
console.log(`Guardado en ${salida} (${Object.keys(respuestas).length} respuestas)`);
