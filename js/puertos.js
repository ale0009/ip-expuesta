// Base local de puertos comunes: qué servicio suele ser, qué riesgo implica en lenguaje claro y qué hacer.
// Es una guía general: un puerto abierto no prueba que haya una falla, y el número no garantiza el servicio.

export const RIESGOS = {
  alto: { titulo: 'Riesgo alto', corta: 'Alto', orden: 0 },
  medio: { titulo: 'Riesgo medio', corta: 'Medio', orden: 1 },
  desconocido: { titulo: 'Sin ficha', corta: '¿?', orden: 2 },
  bajo: { titulo: 'Riesgo bajo', corta: 'Bajo', orden: 3 },
};

export const ACCIONES = {
  cerrar: { titulo: 'Ciérralo', detalle: 'No debería verse desde Internet: déjalo solo en la red interna o detrás de una VPN.' },
  restringir: { titulo: 'Limítalo', detalle: 'Déjalo solo si lo necesitas, y únicamente para las IP o la VPN que lo usan.' },
  normal: { titulo: 'Normal', detalle: 'Es lo esperable si ofreces ese servicio. Mantén el software al día.' },
  revisar: { titulo: 'Averigua', detalle: 'No está en la base: confirma qué programa responde ahí y si alguien lo usa.' },
};

// [puerto, servicio, qué es, riesgo, acción, por qué (lenguaje claro), productos CPE que suelen responder ahí]
const FILAS = [
  [21, 'FTP', 'Transferencia de archivos', 'alto', 'cerrar', 'Usuario y contraseña viajan sin cifrar, y los robots prueban claves sin parar. Cámbialo por SFTP o por una web con HTTPS.', ['vsftpd', 'proftpd', 'pure-ftpd', 'filezilla_server', 'ftp']],
  [22, 'SSH', 'Administración remota cifrada', 'medio', 'restringir', 'El cifrado es bueno, pero recibe miles de intentos de contraseña al día. Usa solo llaves, sin entrar como root, y limítalo a tus IP o a una VPN.', ['openssh', 'dropbear_ssh', 'dropbear_ssh_server']],
  [23, 'Telnet', 'Consola remota antigua', 'alto', 'cerrar', 'Todo viaja en texto plano, contraseña incluida. Es la puerta favorita de botnets como Mirai, que entran con claves de fábrica.', ['telnet']],
  [25, 'SMTP', 'Correo entre servidores', 'medio', 'normal', 'Normal en un servidor de correo. El peligro es que sea un «relé abierto» que deja a cualquiera mandar spam en tu nombre.', ['postfix', 'exim', 'sendmail', 'exchange_server']],
  [53, 'DNS', 'Resolución de nombres', 'medio', 'restringir', 'Normal en un servidor DNS. Si responde preguntas recursivas de cualquiera (resolvedor abierto) sirve para amplificar ataques de denegación de servicio.', ['bind', 'dnsmasq', 'unbound', 'powerdns']],
  [69, 'TFTP', 'Archivos sin contraseña', 'alto', 'cerrar', 'No pide clave: cualquiera puede bajar (o subir) archivos, como las configuraciones de routers y teléfonos IP.', []],
  [80, 'HTTP', 'Web sin cifrar', 'bajo', 'normal', 'Normal en un sitio web, pero lo que viaja se puede leer y alterar en el camino. Debería solo redirigir a HTTPS.', ['http_server', 'nginx', 'internet_information_services', 'iis', 'lighttpd', 'cloudflare', 'litespeed_web_server', 'tomcat']],
  [110, 'POP3', 'Bajar correo (sin cifrar)', 'medio', 'restringir', 'Usuario y contraseña pueden viajar en claro. Prefiere POP3S (995) o IMAPS (993).', ['dovecot']],
  [111, 'rpcbind', 'Directorio de servicios RPC (Unix, NFS)', 'alto', 'cerrar', 'Le cuenta a cualquiera qué servicios internos tienes y se usa para amplificar ataques DDoS.', []],
  [123, 'NTP', 'Hora de red', 'medio', 'restringir', 'Mal configurado responde a la orden «monlist» y multiplica el tráfico de un ataque DDoS.', ['ntp']],
  [135, 'MSRPC', 'Llamadas remotas de Windows', 'alto', 'cerrar', 'Expone el corazón de una red Windows; gusanos como Blaster entraron por aquí.', []],
  [137, 'NetBIOS-NS', 'Nombres de red de Windows', 'alto', 'cerrar', 'Revela nombres de equipos y grupos de trabajo. No tiene por qué salir de la red interna.', []],
  [139, 'NetBIOS', 'Carpetas compartidas de Windows (antiguo)', 'alto', 'cerrar', 'Expone carpetas compartidas y nombres de usuario a quien pregunte.', ['samba']],
  [143, 'IMAP', 'Leer correo (sin cifrar)', 'medio', 'restringir', 'La contraseña puede viajar en claro si no se fuerza el cifrado. Prefiere IMAPS (993).', ['dovecot']],
  [161, 'SNMP', 'Monitoreo de equipos de red', 'alto', 'cerrar', 'Con la clave de fábrica «public» entrega la configuración completa del equipo.', []],
  [389, 'LDAP', 'Directorio de usuarios', 'alto', 'cerrar', 'Expone el directorio de cuentas (por ejemplo, Active Directory) y se usa para amplificar DDoS.', ['openldap']],
  [443, 'HTTPS', 'Web cifrada', 'bajo', 'normal', 'Es lo esperable en un sitio web. El riesgo no está en el puerto sino en el software y la aplicación que hay detrás.', ['http_server', 'nginx', 'internet_information_services', 'iis', 'lighttpd', 'cloudflare', 'litespeed_web_server', 'tomcat']],
  [445, 'SMB', 'Archivos compartidos de Windows', 'alto', 'cerrar', 'Por aquí se propagó WannaCry (EternalBlue). Nunca debería estar abierto a Internet.', ['samba']],
  [465, 'SMTPS', 'Envío de correo cifrado', 'bajo', 'normal', 'Normal en un servidor de correo. Vigila los intentos de adivinar contraseñas de las cuentas.', ['postfix', 'exim']],
  [587, 'Submission', 'Envío de correo autenticado', 'bajo', 'normal', 'Normal en un servidor de correo. Vigila los intentos de adivinar contraseñas de las cuentas.', ['postfix', 'exim']],
  [631, 'IPP', 'Impresión (CUPS)', 'medio', 'cerrar', 'Una impresora o un servidor CUPS a la vista permite imprimir a extraños y explotar fallas como las de CUPS de 2024.', ['cups']],
  [853, 'DoT', 'DNS cifrado (DNS sobre TLS)', 'bajo', 'normal', 'Normal en un resolvedor DNS que ofrece cifrado a sus usuarios.', ['unbound', 'bind']],
  [993, 'IMAPS', 'Leer correo cifrado', 'bajo', 'normal', 'Normal en un servidor de correo. Vigila los intentos de adivinar contraseñas.', ['dovecot']],
  [995, 'POP3S', 'Bajar correo cifrado', 'bajo', 'normal', 'Normal en un servidor de correo. Vigila los intentos de adivinar contraseñas.', ['dovecot']],
  [1433, 'MS SQL', 'Base de datos SQL Server', 'alto', 'cerrar', 'Una base de datos no debe hablar directo con Internet; los robots prueban la cuenta «sa» con claves débiles.', ['sql_server']],
  [1521, 'Oracle', 'Base de datos Oracle', 'alto', 'cerrar', 'Una base de datos no debe hablar directo con Internet: quien llegue puede probar cuentas y fallas del motor.', ['database_server']],
  [1723, 'PPTP', 'VPN antigua', 'alto', 'cerrar', 'Su cifrado se considera roto desde 2012. Cámbiala por WireGuard, OpenVPN o IPsec.', []],
  [1883, 'MQTT', 'Mensajes de dispositivos IoT', 'alto', 'cerrar', 'Suele ir sin clave ni cifrado: cualquiera puede leer los sensores y mandar órdenes a los aparatos.', ['mosquitto']],
  [2049, 'NFS', 'Disco compartido de red (Unix)', 'alto', 'cerrar', 'Un recurso NFS mal exportado deja montar tus archivos desde cualquier lugar.', []],
  [2375, 'Docker', 'API de Docker sin cifrar', 'alto', 'cerrar', 'Da control total del servidor sin pedir clave. Se usa para instalar mineros de criptomonedas en equipos ajenos.', ['docker']],
  [3306, 'MySQL', 'Base de datos MySQL / MariaDB', 'alto', 'cerrar', 'Una base de datos no debe hablar directo con Internet: es blanco de fuerza bruta y de robo de datos.', ['mysql', 'mariadb']],
  [3389, 'RDP', 'Escritorio remoto de Windows', 'alto', 'cerrar', 'Entrada número uno del ransomware: fuerza bruta de contraseñas y fallas como BlueKeep. Ponlo detrás de una VPN.', ['remote_desktop_services']],
  [5060, 'SIP', 'Telefonía IP', 'medio', 'restringir', 'Hay robots que buscan centralitas abiertas para hacer llamadas internacionales a costa tuya.', ['asterisk']],
  [5432, 'PostgreSQL', 'Base de datos PostgreSQL', 'alto', 'cerrar', 'Una base de datos no debe hablar directo con Internet: es blanco de fuerza bruta y de robo de datos.', ['postgresql']],
  [5900, 'VNC', 'Control remoto de pantalla', 'alto', 'cerrar', 'Muchas instalaciones van sin clave o con una débil: quien entra ve y maneja la pantalla.', ['vnc', 'realvnc', 'tightvnc']],
  [5985, 'WinRM', 'Administración remota de Windows', 'alto', 'cerrar', 'Permite ejecutar órdenes de PowerShell en el servidor si se adivina una cuenta.', []],
  [6379, 'Redis', 'Base de datos en memoria', 'alto', 'cerrar', 'Por defecto no pide clave: se puede leer todo y hasta escribir archivos en el servidor.', ['redis']],
  [8080, 'HTTP alterno', 'Web secundaria, panel o proxy', 'medio', 'restringir', 'Suele ser un panel de administración o un servidor de pruebas que se quedó abierto por descuido.', ['http_server', 'nginx', 'tomcat', 'jetty', 'cloudflare']],
  [8443, 'HTTPS alterno', 'Panel web cifrado', 'medio', 'restringir', 'Suele ser el panel de administración de un router, firewall o servidor: no debería verlo todo el mundo.', ['http_server', 'nginx', 'tomcat', 'cloudflare']],
  [9200, 'Elasticsearch', 'Motor de búsqueda y registros', 'alto', 'cerrar', 'Causa de muchas filtraciones masivas: sin clave, cualquiera descarga los índices completos.', ['elasticsearch']],
  [11211, 'Memcached', 'Caché en memoria', 'alto', 'cerrar', 'Sin clave y por UDP permitió el ataque DDoS récord de 1,35 Tbps contra GitHub en 2018.', ['memcached']],
  [27017, 'MongoDB', 'Base de datos NoSQL', 'alto', 'cerrar', 'Miles de bases abiertas sin clave fueron borradas y «secuestradas» a cambio de un rescate.', ['mongodb']],
];

export const BASE = FILAS.map(([puerto, servicio, que, riesgo, accion, porque, productos]) => ({ puerto, servicio, que, riesgo, accion, porque, productos }));
export const PORT_A_FICHA = new Map(BASE.map((f) => [f.puerto, f]));

/** "cpe:/a:apache:http_server:2.4.7" o "cpe:2.3:a:apache:http_server:2.4.7:…" → { parte, proveedor, producto, version, texto }. */
export function leerCpe(cpe) {
  const s = String(cpe ?? '');
  const p = s.startsWith('cpe:2.3:') ? s.slice(8).split(':') : s.startsWith('cpe:/') ? s.slice(5).split(':') : null;
  if (!p || p.length < 3) return null;
  const limpio = (x) => (x && x !== '*' && x !== '-' ? x.replace(/\\(.)/g, '$1') : '');
  const [parte, proveedor, producto, version] = p.map(limpio);
  const tipo = { a: 'aplicación', o: 'sistema operativo', h: 'equipo' }[parte] ?? 'otro';
  return { cpe: s, parte, tipo, proveedor, producto, version, texto: [proveedor === producto ? '' : proveedor, producto.replace(/_/g, ' '), version].filter(Boolean).join(' ') };
}

/**
 * Puertos de InternetDB (+ CPE) → lista ordenada (riesgo, luego número) de
 * { puerto, ficha | null, servicio, riesgo, accion, software: [cpe leído] }.
 * El software se asocia a un puerto solo si su producto suele responder ahí (heurística: InternetDB no lo dice).
 */
export function evaluarPuertos(puertos = [], cpes = []) {
  const leidos = cpes.map(leerCpe).filter(Boolean);
  const unicos = [...new Set(puertos.map(Number).filter((p) => Number.isInteger(p) && p > 0 && p < 65536))];
  return unicos.map((puerto) => {
    const ficha = PORT_A_FICHA.get(puerto) ?? null;
    return {
      puerto,
      ficha,
      servicio: ficha?.servicio ?? 'Desconocido',
      riesgo: ficha?.riesgo ?? 'desconocido',
      accion: ficha?.accion ?? 'revisar',
      software: ficha ? leidos.filter((c) => ficha.productos.includes(c.producto)) : [],
    };
  }).sort((a, b) => RIESGOS[a.riesgo].orden - RIESGOS[b.riesgo].orden || a.puerto - b.puerto);
}

/** CPE que no quedaron pegados a ningún puerto (p. ej., el sistema operativo). */
export function softwareSuelto(evaluados, cpes = []) {
  const usados = new Set(evaluados.flatMap((e) => e.software.map((s) => s.cpe)));
  return cpes.map(leerCpe).filter((c) => c && !usados.has(c.cpe));
}

const cuenta = (lista, clave) => Object.fromEntries(Object.keys(clave === 'riesgo' ? RIESGOS : ACCIONES).map((k) => [k, lista.filter((e) => e[clave] === k).length]));

/**
 * Veredicto general. estadoIdb: 'ok' | 'vacio' | 'error'.
 * alto: algún puerto de riesgo alto · medio: alguno medio o sin ficha, o hay CVE · bajo: solo puertos de riesgo bajo.
 */
export function veredicto({ estadoIdb, evaluados = [], nVulns = 0 }) {
  const riesgos = cuenta(evaluados, 'riesgo');
  const acciones = cuenta(evaluados, 'accion');
  let nivel;
  if (estadoIdb === 'error') nivel = 'error';
  else if (estadoIdb === 'vacio' || (!evaluados.length && !nVulns)) nivel = 'nada';
  else if (riesgos.alto) nivel = 'alto';
  else if (riesgos.medio || riesgos.desconocido || nVulns) nivel = 'medio';
  else nivel = 'bajo';
  return { nivel, puertos: evaluados.length, riesgos, acciones, nVulns };
}

/** Cifras de la propia base (para /proceso/, «calculado aquí»). */
export function resumenBase(base = BASE) {
  return {
    total: base.length,
    riesgos: cuenta(base, 'riesgo'),
    acciones: cuenta(base, 'accion'),
    altoCerrar: base.filter((f) => f.riesgo === 'alto' && f.accion === 'cerrar').length,
    basesDatos: base.filter((f) => /^Base de datos/.test(f.que)).length,
  };
}
