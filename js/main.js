// Página principal: lee la entrada, consulta las fuentes pasivas (o el respaldo) y pinta veredicto, puertos y CVE.
import { iniciarTema } from './tema.js';
import { analizarEntrada } from './entrada.js';
import { consultar, crearPedirVivo, crearPedirGuardado, crearPedirConRespaldo } from './consulta.js';
import { evaluarPuertos, softwareSuelto, veredicto, RIESGOS, ACCIONES } from './puertos.js';
import { ordenarCves, porAnio, enlaceCve, enlaceLote } from './cves.js';
import { barrasAnios } from './graficas.js';
import { proveedorPublico, NOTA_PROVEEDOR } from './proveedores.js';

const $ = (id) => document.getElementById(id);
const RESPALDO = { ruta: 'datos/ejemplo-2026-11-10.json', fecha: '10 nov 2026' };
const EJEMPLO_INICIAL = 'scanme.nmap.org';
const MAX_CHIPS = 30;

const params = new URLSearchParams(location.search);
const sinConexion = params.has('sin-conexion');
const nf = new Intl.NumberFormat('es-CO');
let paises = null;
try { paises = new Intl.DisplayNames(['es'], { type: 'region' }); } catch { /* navegador antiguo: se muestra el código */ }
let turno = 0;
let ultimo = null;

function el(tag, attrs = {}, ...hijos) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k === 'class') n.className = v; else if (k === 'text') n.textContent = v; else n.setAttribute(k, v);
  }
  for (const h of hijos) if (h != null && h !== false) n.append(h);
  return n;
}

let respaldoProm = null;
function cargarRespaldo() {
  respaldoProm ??= fetch(RESPALDO.ruta).then((r) => {
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.json();
  }).catch(() => { respaldoProm = null; return null; });
  return respaldoProm;
}

const plural = (n, uno, varios) => `${nf.format(n)} ${n === 1 ? uno : varios}`;
const TONO = { alto: 'rojo', medio: 'medio', bajo: 'frio', nada: 'calma', error: 'error', privada: 'frio' };
const SELLO = { alto: 'ALTO', medio: 'OJO', bajo: 'BIEN', nada: 'VACÍO', error: '?', privada: 'LAN' };
const ONOMA = { alto: '¡EXPUESTO!', medio: 'HMM…', bajo: 'OK', nada: 'SILENCIO', error: '¿?', privada: 'PRIVADO' };

function cabeza(nivel, pregunta, titulo, sub) {
  const caja = $('respuesta');
  caja.dataset.tono = TONO[nivel] ?? 'calma';
  caja.setAttribute('aria-busy', 'false');
  $('sello').textContent = SELLO[nivel] ?? '?';
  $('onoma').textContent = ONOMA[nivel] ?? '';
  $('pregunta').textContent = pregunta;
  $('veredicto').textContent = titulo;
  $('sub-veredicto').replaceChildren(...[sub].flat().filter(Boolean));
}

function pintarCarga(texto) {
  const caja = $('respuesta');
  caja.dataset.tono = 'carga';
  caja.setAttribute('aria-busy', 'true');
  $('onoma').textContent = 'OTEANDO…';
  $('sello').textContent = '…';
  $('pregunta').textContent = `Consultando ${texto}`;
  $('veredicto').replaceChildren(el('span', { class: 'cargando-txt', text: 'Preguntando a Shodan, RIPE y al DNS…' }));
  $('sub-veredicto').textContent = 'Sin tocar la IP: solo bases de datos públicas.';
  $('senales').replaceChildren(...['Red', 'Prefijo', 'País', 'Nombre inverso'].map((t) => el('div', { class: 'senal esqueleto', 'aria-hidden': 'true' }, el('p', { class: 'senal-t', text: t }))));
  $('estado').replaceChildren(el('span', { class: 'chip chip-carga', text: 'Cargando' }));
  $('tarjetas').replaceChildren(...[1, 2, 3].map(() => el('li', { class: 'tarjeta esqueleto', 'aria-hidden': 'true' })));
  $('resumen-puertos').textContent = '';
  $('cves-cuerpo').replaceChildren(el('p', { class: 'ayuda', text: 'Cargando…' }));
}

function vaciarPaneles(textoPuertos, textoCves) {
  $('senales').replaceChildren();
  $('tarjetas').replaceChildren(el('li', { class: 'tarjeta vacia' }, el('p', { text: textoPuertos })));
  $('resumen-puertos').textContent = '';
  $('cves-cuerpo').replaceChildren(el('p', { class: 'ayuda', text: textoCves }));
}

function chipsEstado(fuentes, origen) {
  const chips = [];
  if (origen === 'respaldo') chips.push(el('span', { class: 'chip chip-ejemplo', text: `Sin conexión: datos de ejemplo del ${RESPALDO.fecha}` }));
  else if (origen === 'mixto') chips.push(el('span', { class: 'chip chip-ejemplo', text: `Parte de los datos son de ejemplo (${RESPALDO.fecha}): alguna fuente no respondió` }));
  else chips.push(el('span', { class: 'chip chip-vivo', text: 'En vivo' }));
  const txt = { ok: 'ok', vacio: 'sin datos', error: 'falló' };
  for (const [nombre, f] of fuentes) {
    chips.push(el('span', { class: `chip chip-fuente f-${f.estado === 'error' ? 'error' : f.estado === 'vacio' ? 'parcial' : 'ok'}`, title: f.detalle ?? null, text: `${nombre}: ${txt[f.estado] ?? f.estado}` }));
  }
  const errores = fuentes.filter(([, f]) => f.estado === 'error');
  if (errores.length) chips.push(el('span', { class: 'motivo', text: `Qué falló: ${errores.map(([n, f]) => `${n} (${f.detalle})`).join(' · ')}` }));
  return chips;
}

function senal(titulo, valor, nota, clase = '') {
  return el('div', { class: `senal ${clase}` }, el('p', { class: 'senal-t', text: titulo }), el('p', { class: 'senal-v senal-txt', text: valor }), nota ? el('p', { class: 'senal-n', text: nota }) : null);
}

function pintarSenales(r) {
  const s = [];
  const red = r.red;
  s.push(red.estado === 'ok'
    ? senal('Red (ASN)', `AS${red.asn}`, red.titular + (red.otrosAsn.length ? ` · y ${red.otrosAsn.length} más` : ''))
    : senal('Red (ASN)', '–', red.estado === 'vacio' ? 'Nadie anuncia esta IP en Internet ahora mismo.' : 'RIPEstat no respondió.'));
  s.push(senal('Prefijo', red.prefijo ?? '–', red.bloque ? `Bloque: ${red.bloque.length > 60 ? `${red.bloque.slice(0, 58)}…` : red.bloque}` : null));
  const pais = r.geo.pais ? (paises?.of(r.geo.pais) ?? r.geo.pais) : '–';
  s.push(senal('País aproximado', pais, r.geo.estado === 'ok' ? 'Según MaxMind GeoLite. En redes anycast es solo una pista.' : r.geo.estado === 'vacio' ? 'MaxMind no lo sabe (típico de redes anycast).' : 'No se pudo consultar.'));
  const ptr = r.ptr.valores?.[0];
  s.push(senal('Nombre inverso (PTR)', ptr ?? 'sin nombre', ptr ? 'Lo que responde el DNS al preguntar por la IP.' : r.ptr.estado === 'error' ? 'El DNS no respondió.' : 'La IP no tiene registro PTR.', 'senal-ptr'));
  const extra = [];
  if (r.idb.estado === 'ok' && r.idb.nombres.length) extra.push(el('div', { class: 'senal senal-ancha' }, el('p', { class: 'senal-t', text: `Nombres que Shodan vio (${r.idb.nombres.length})` }), el('p', { class: 'senal-n nombres', text: r.idb.nombres.slice(0, 8).join(' · ') + (r.idb.nombres.length > 8 ? ' …' : '') })));
  if (r.idb.estado === 'ok' && r.idb.etiquetas.length) extra.push(el('div', { class: 'senal senal-ancha' }, el('p', { class: 'senal-t', text: 'Etiquetas de Shodan' }), el('p', { class: 'senal-n', text: r.idb.etiquetas.map(etiquetaShodan).join(' · ') })));
  $('senales').replaceChildren(...s, ...extra);
}

const ETIQUETAS = { cloud: 'nube (proveedor de hosting)', cdn: 'CDN', vpn: 'VPN', tor: 'nodo Tor', honeypot: 'posible honeypot (señuelo)', proxy: 'proxy', self_signed: 'certificado autofirmado', starttls: 'STARTTLS', database: 'base de datos', iot: 'dispositivo IoT', ics: 'control industrial', pqc: 'cifrado poscuántico', 'eol-os': 'sistema operativo sin soporte', 'eol-product': 'producto sin soporte', compromised: 'posiblemente comprometido', malware: 'malware', c2: 'servidor de mando de malware', scanner: 'escáner', videogame: 'videojuego', medical: 'equipo médico', devops: 'DevOps', doublepulsar: 'DoublePulsar (implante)' };
const etiquetaShodan = (t) => ETIQUETAS[t] ?? t;

function tarjeta(e) {
  const f = e.ficha;
  const a = ACCIONES[e.accion];
  return el('li', { class: `tarjeta r-${e.riesgo}` },
    el('div', { class: 'tarjeta-cab' },
      el('span', { class: 'num-puerto', text: String(e.puerto) }),
      el('span', { class: 'servicio' }, el('strong', { text: e.servicio }), el('small', { text: f?.que ?? 'No está en la base de 42 puertos' })),
      el('span', { class: `pastilla t-${e.riesgo}`, text: RIESGOS[e.riesgo].titulo })),
    el('p', { class: 'porque', text: f?.porque ?? 'Puede ser un servicio a medida, un panel o algo que alguien olvidó. Un puerto que nadie sabe explicar es justo el que hay que revisar.' }),
    e.software.length ? el('p', { class: 'software' }, el('span', { class: 'etiqueta', text: 'Software anunciado' }), e.software.map((c) => c.texto).join(' · ')) : null,
    el('p', { class: `accion a-${e.accion}` }, el('strong', { text: `¿Cerrarlo? ${a.titulo}.` }), ` ${a.detalle}`));
}

// Los puertos que no están en la base van juntos en una sola tarjeta: comparten el mismo consejo.
function tarjetaSinFicha(lista) {
  const a = ACCIONES.revisar;
  return el('li', { class: 'tarjeta r-desconocido' },
    el('div', { class: 'tarjeta-cab' },
      el('span', { class: 'num-puerto', text: '¿?' }),
      el('span', { class: 'servicio' }, el('strong', { text: plural(lista.length, 'puerto sin ficha', 'puertos sin ficha') }), el('small', { text: 'No están en la base de 42 puertos comunes' })),
      el('span', { class: 'pastilla t-desconocido', text: RIESGOS.desconocido.titulo })),
    el('p', { class: 'nums-sueltos', text: lista.map((e) => e.puerto).join(' · ') }),
    el('p', { class: 'porque', text: 'Pueden ser servicios a medida, paneles o algo que alguien olvidó. Un puerto que nadie sabe explicar es justo el que hay que revisar.' }),
    el('p', { class: 'accion a-revisar' }, el('strong', { text: `¿Cerrarlos? ${a.titulo}.` }), ` ${a.detalle}`));
}

function pintarPuertos(evaluados, v) {
  if (!evaluados.length) {
    $('tarjetas').replaceChildren(el('li', { class: 'tarjeta vacia' }, el('p', { text: 'Shodan no registra puertos abiertos en esta IP.' })));
    $('resumen-puertos').textContent = '';
    return;
  }
  const conFicha = evaluados.filter((e) => e.ficha);
  const sinFicha = evaluados.filter((e) => !e.ficha);
  $('tarjetas').replaceChildren(...conFicha.map(tarjeta), sinFicha.length ? tarjetaSinFicha(sinFicha) : null);
  const partes = [['alto', 'alto'], ['medio', 'medio'], ['bajo', 'bajo'], ['desconocido', 'sin ficha']]
    .filter(([k]) => v.riesgos[k]).map(([k, t]) => `${v.riesgos[k]} ${t}`);
  $('resumen-puertos').textContent = `${plural(evaluados.length, 'puerto', 'puertos')} · riesgo ${partes.join(' · ')}`;
}

function pintarCves(r, ev) {
  const caja = $('cves-cuerpo');
  const ids = ordenarCves(r.idb.vulns);
  const suelto = softwareSuelto(ev, r.idb.cpes);
  const nodos = [];
  if (!ids.length) {
    nodos.push(el('p', { class: 'cves-cero' }, el('span', { class: 'cifra-grande', text: '0' }), el('span', { text: 'CVE asociados. Shodan no encontró versiones de software con vulnerabilidades conocidas (o no pudo leer las versiones).' })));
  } else {
    const serie = porAnio(ids);
    const recientes = ids.filter((id) => Number(id.slice(4, 8)) >= serie[serie.length - 1][0] - 1).length;
    nodos.push(el('p', { class: 'cves-cero' }, el('span', { class: 'cifra-grande rojo', text: nf.format(ids.length) }), el('span', { text: `CVE por la versión del software anunciado; ${nf.format(recientes)} con identificador de ${serie[serie.length - 1][0] - 1} o ${serie[serie.length - 1][0]} (en rojo).` })));
    const g = el('div', { class: 'g-caja g-anios' });
    g.innerHTML = barrasAnios(serie, { ancho: Math.max(300, Math.min(620, caja.clientWidth || 520)), titulo: 'CVE asociados por año del identificador' });
    nodos.push(g);
    nodos.push(el('p', { class: 'nota-cve' }, 'Ojo: InternetDB no dice a qué puerto pertenece cada CVE ni si de verdad aplica. Los cruza por versión, y muchas distribuciones (Ubuntu, Debian, Red Hat) corrigen fallos sin cambiar el número: puede haber falsos positivos.'));
    const lista = el('ul', { class: 'lista-cve' }, ...ids.slice(0, MAX_CHIPS).map((id) => el('li', {}, el('a', { href: enlaceCve(id), target: '_blank', rel: 'noopener', text: id }))));
    nodos.push(lista);
    if (ids.length > MAX_CHIPS) {
      const resto = el('details', { class: 'mas-cve' }, el('summary', { text: `Ver los otros ${nf.format(ids.length - MAX_CHIPS)}` }),
        el('ul', { class: 'lista-cve' }, ...ids.slice(MAX_CHIPS).map((id) => el('li', {}, el('a', { href: enlaceCve(id), target: '_blank', rel: 'noopener', text: id })))));
      nodos.push(resto);
    }
    const lote = enlaceLote(ids);
    nodos.push(el('a', { class: 'boton-linea boton-lote', href: lote.url, target: '_blank', rel: 'noopener', text: lote.n === ids.length ? `¿Cuáles se explotan ya? Priorizar los ${lote.n}` : `¿Cuáles se explotan ya? Priorizar los ${lote.n} más recientes` }));
  }
  if (suelto.length) nodos.push(el('div', { class: 'suelto' }, el('p', { class: 'etiqueta', text: 'Otro software anunciado' }), el('p', { text: suelto.map((c) => `${c.texto} (${c.tipo})`).join(' · ') })));
  caja.replaceChildren(...nodos);
}

function pintarResultado(r, origen) {
  ultimo = { r, origen };
  if (r.tipo === 'entrada') {
    cabeza('error', 'Revisa lo que escribiste', 'Eso no es una IP', r.mensaje);
    $('estado').replaceChildren();
    vaciarPaneles('Sin consulta.', 'Sin consulta.');
    return;
  }
  if (r.tipo === 'dns') {
    cabeza('error', r.dominio, r.error ? 'Sin respuesta del DNS' : 'Ese dominio no lleva a ninguna IP', r.mensaje);
    $('estado').replaceChildren(el('span', { class: `chip ${r.error ? 'chip-error' : 'chip-fuente'}`, text: r.error ? 'dns.google: falló' : 'dns.google: ok' }));
    vaciarPaneles('Sin IP no hay nada que mirar.', 'Sin consulta.');
    return;
  }
  if (r.tipo === 'privada') {
    cabeza('privada', r.dominio ? `${r.dominio} → ${r.ip}` : r.ip, 'Internet no la ve',
      `Es una ${r.motivo}. Estas direcciones no salen a Internet, así que no hay registro público. Para revisar una red interna se usa un escáner activo como Nmap, y solo con permiso.`);
    $('estado').replaceChildren(el('span', { class: 'chip chip-fuente', text: 'No se consultó ninguna fuente' }));
    vaciarPaneles('No aplica a direcciones privadas.', 'No aplica a direcciones privadas.');
    return;
  }
  const ev = r.idb.estado === 'ok' ? evaluarPuertos(r.idb.puertos, r.idb.cpes) : [];
  const v = veredicto({ estadoIdb: r.idb.estado, evaluados: ev, nVulns: r.idb.vulns?.length ?? 0 });
  const quien = r.dominio ? `${r.dominio} → ${r.ip}${r.otrasIps.length ? ` (+${r.otrasIps.length} IP)` : ''}` : r.ip;
  if (v.nivel === 'error') {
    cabeza('error', quien, 'Shodan no respondió', `${r.idb.detalle}. La red y el nombre sí se muestran abajo si llegaron.`);
  } else if (v.nivel === 'nada') {
    cabeza('nada', quien, 'Nada a la vista', 'Shodan no tiene puertos registrados para esta IP. No prueba que esté cerrada: solo que no hay registro público reciente.');
  } else {
    const acc = [['cerrar', 'para cerrar', 'para cerrar'], ['restringir', 'para limitar', 'para limitar'], ['normal', 'normal', 'normales'], ['revisar', 'sin ficha', 'sin ficha']]
      .filter(([k]) => v.acciones[k]).map(([k, uno, varios]) => plural(v.acciones[k], uno, varios));
    const sub = [acc.join(' · ')];
    if (v.nVulns) sub.push(el('span', { class: 'regla', text: ` · ${plural(v.nVulns, 'CVE asociado', 'CVE asociados')}` }));
    const prov = proveedorPublico(r.red);
    if (prov) sub.push(el('span', { class: 'nota-proveedor', text: `${prov}. ${NOTA_PROVEEDOR}` }));
    cabeza(v.nivel, quien, v.puertos ? `${plural(v.puertos, 'puerto', 'puertos')} a la vista` : 'Sin puertos, con CVE', sub);
  }
  pintarSenales(r);
  $('estado').replaceChildren(...chipsEstado([['InternetDB', r.idb], ['RIPEstat', r.red], ['GeoLite', r.geo], ['DNS', r.ptr]], origen));
  if (r.idb.estado === 'ok') { pintarPuertos(ev, v); pintarCves(r, ev); } else {
    $('tarjetas').replaceChildren(el('li', { class: 'tarjeta vacia' }, el('p', { text: v.nivel === 'nada' ? 'Shodan no registra puertos abiertos en esta IP.' : 'Sin datos de InternetDB.' })));
    $('resumen-puertos').textContent = '';
    $('cves-cuerpo').replaceChildren(el('p', { class: 'ayuda', text: v.nivel === 'nada' ? 'Sin puertos ni software registrados, no hay CVE que asociar.' : 'Sin datos de InternetDB.' }));
  }
}

async function ejecutar(texto) {
  const yo = ++turno;
  const e = analizarEntrada(texto);
  const ayuda = $('ayuda-entrada');
  if (e.tipo === 'vacia' || e.tipo === 'invalida') {
    ayuda.textContent = e.mensaje;
    ayuda.classList.add('error');
    $('entrada').setAttribute('aria-invalid', 'true');
    $('consultar').disabled = false;
    pintarResultado({ tipo: 'entrada', mensaje: e.mensaje, valor: e.valor }, 'vivo');
    return;
  }
  ayuda.classList.remove('error');
  ayuda.textContent = e.tipo === 'dominio' ? `Dominio: primero busco su IP en el DNS.` : `${e.tipo === 'ipv6' ? 'IPv6' : 'IPv4'}: ${e.valor}`;
  $('entrada').removeAttribute('aria-invalid');
  const url = new URL(location.href);
  url.searchParams.set('ip', e.valor);
  history.replaceState(null, '', url);
  for (const b of document.querySelectorAll('[data-ejemplo]')) b.setAttribute('aria-pressed', String(b.dataset.ejemplo === e.valor));
  $('consultar').disabled = true;
  pintarCarga(e.valor);

  const respaldo = await cargarRespaldo();
  const guardado = crearPedirGuardado(respaldo);
  let pedir;
  let origen = 'vivo';
  if (sinConexion) {
    pedir = guardado;
    origen = 'respaldo';
  } else {
    pedir = respaldo ? crearPedirConRespaldo(crearPedirVivo(), guardado) : crearPedirVivo();
  }
  const r = await consultar(texto, pedir);
  if (yo !== turno) return;
  $('consultar').disabled = false;
  if (pedir.usados?.size) origen = 'mixto';
  if (sinConexion && r.tipo === 'ok' && r.idb.estado === 'error') {
    cabeza('error', 'Modo sin conexión', 'Sin datos guardados', `Con ?sin-conexion solo funcionan los ejemplos: ${respaldo?.entradas?.slice(0, 5).join(', ') ?? 'no disponibles'}.`);
    $('estado').replaceChildren(el('span', { class: 'chip chip-ejemplo', text: `Sin conexión: datos de ejemplo del ${RESPALDO.fecha}` }));
    vaciarPaneles('Sin datos guardados para esta IP.', 'Sin datos guardados.');
    return;
  }
  pintarResultado(r, origen);
}

// ------------------------------------------------------------------ arranque
iniciarTema($('tema'));
$('form').addEventListener('submit', (ev) => { ev.preventDefault(); ejecutar($('entrada').value); });
for (const b of document.querySelectorAll('[data-ejemplo]')) {
  b.addEventListener('click', () => { $('entrada').value = b.dataset.ejemplo; ejecutar(b.dataset.ejemplo); });
}
let espera = null;
addEventListener('resize', () => {
  clearTimeout(espera);
  espera = setTimeout(() => { if (ultimo?.r?.tipo === 'ok' && ultimo.r.idb.estado === 'ok') pintarCves(ultimo.r, evaluarPuertos(ultimo.r.idb.puertos, ultimo.r.idb.cpes)); }, 150);
});

const inicial = params.get('ip') || EJEMPLO_INICIAL;
$('entrada').value = inicial;
ejecutar(inicial);
