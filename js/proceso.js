// Página /proceso/: tema, cifras de la base de puertos y de los ejemplos guardados («calculado aquí»).
import { iniciarTema } from './tema.js';
import { resumenBase, evaluarPuertos, veredicto, RIESGOS } from './puertos.js';
import { consultar, crearPedirGuardado } from './consulta.js';
import { porAnio } from './cves.js';
import { barrasH, barrasAnios } from './graficas.js';

const $ = (id) => document.getElementById(id);
const DATOS = '../datos/ejemplo-2026-11-10.json';
const pc = (a, b) => `${new Intl.NumberFormat('es-CO', { maximumFractionDigits: 0 }).format((a / b) * 100)} %`;
const dato = (clave, texto) => { for (const n of document.querySelectorAll(`[data-dato="${clave}"]`)) n.textContent = texto; };
const ancho = (id) => Math.max(300, Math.min(560, $(id).clientWidth || 520));

function pintarBase() {
  const r = resumenBase();
  dato('b-total', String(r.total));
  dato('b-alto', String(r.riesgos.alto));
  dato('b-pc', pc(r.riesgos.alto, r.total));
  dato('b-bd', String(r.basesDatos));
  dato('b-normal', String(r.acciones.normal));
  $('g-riesgo').innerHTML = barrasH(['alto', 'medio', 'bajo'].map((k) => ({ etiqueta: RIESGOS[k].titulo, valor: r.riesgos[k], clase: `r-${k}` })), { ancho: ancho('g-riesgo'), etiqueta: 120, titulo: 'Puertos de la base por nivel de riesgo' });
  $('g-accion').innerHTML = barrasH([['cerrar', 'Ciérralo'], ['restringir', 'Limítalo'], ['normal', 'Normal']].map(([k, t]) => ({ etiqueta: t, valor: r.acciones[k], clase: `a-${k}` })), { ancho: ancho('g-accion'), etiqueta: 120, titulo: 'Puertos de la base por recomendación' });
}

async function pintarEjemplos() {
  try {
    const resp = await fetch(DATOS);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const datos = await resp.json();
    const pedir = crearPedirGuardado(datos);
    const filas = [];
    for (const e of datos.entradas) {
      const r = await consultar(e, pedir);
      if (r.tipo !== 'ok') continue;
      const ev = r.idb.estado === 'ok' ? evaluarPuertos(r.idb.puertos, r.idb.cpes) : [];
      const v = veredicto({ estadoIdb: r.idb.estado, evaluados: ev, nVulns: r.idb.vulns?.length ?? 0 });
      filas.push({ e, r, v });
      if (e === 'scanme.nmap.org') {
        const serie = porAnio(r.idb.vulns);
        const viejos = r.idb.vulns.filter((id) => Number(id.slice(4, 8)) < 2014).length;
        const ultimo = serie[serie.length - 1];
        dato('s-viejos', String(viejos));
        $('g-scanme').innerHTML = barrasAnios(serie, { ancho: Math.max(300, Math.min(900, $('g-scanme').clientWidth || 700)), desde: ultimo[0], titulo: 'CVE de scanme.nmap.org por año' });
        $('cap-scanme').textContent = `${r.idb.vulns.length} CVE asociados, casi todos por Apache 2.4.7. ${ultimo[1]} (${pc(ultimo[1], r.idb.vulns.length)}) tienen identificador de ${ultimo[0]}, en rojo; ${viejos} son anteriores a 2014. Cifras calculadas aquí con la respuesta de InternetDB del 10 nov 2026.`;
      }
    }
    const nivel = { alto: 'Alto', medio: 'Medio', bajo: 'Bajo', nada: 'Sin datos', error: 'Error' };
    $('tabla-ejemplos').replaceChildren(...filas.map(({ e, r, v }) => {
      const tr = document.createElement('tr');
      const a = v.acciones;
      const celdas = [r.dominio ? `${e} (${r.ip})` : e, nivel[v.nivel], String(v.puertos), `${a.cerrar} · ${a.restringir} · ${a.normal} · ${a.revisar}`, String(v.nVulns)];
      celdas.forEach((t, i) => {
        const td = document.createElement('td');
        td.textContent = t;
        if (i === 2 || i === 4) td.className = 'num';
        tr.append(td);
      });
      return tr;
    }));
  } catch (err) {
    $('tabla-ejemplos').replaceChildren();
    $('cap-scanme').textContent = `No se pudieron cargar los datos guardados (${err.message}).`;
  }
}

iniciarTema($('tema'));
pintarBase();
pintarEjemplos();
