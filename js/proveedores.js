// Redes (ASN) de grandes proveedores con infraestructura pública o anycast: resolvedores DNS, CDN y nubes.
// Sus puertos visibles son parte del servicio que ofrecen, no el descuido de un cliente.
export const PROVEEDORES = new Map([
  [13335, 'Cloudflare'],
  [15169, 'Google'],
  [396982, 'Google Cloud'],
  [19281, 'Quad9'],
  [36692, 'Cisco OpenDNS'],
  [20940, 'Akamai'],
  [16625, 'Akamai'],
  [54113, 'Fastly'],
  [16509, 'Amazon'],
  [14618, 'Amazon'],
  [8075, 'Microsoft'],
  [8068, 'Microsoft'],
]);

export const NOTA_PROVEEDOR = 'Infraestructura pública de un proveedor: el nivel describe puertos visibles, no un descuido.';

/** Resultado de leerPrefijo() → nombre del proveedor si su ASN es de la lista, o null. */
export function proveedorPublico(red) {
  if (red?.estado !== 'ok') return null;
  for (const asn of [red.asn, ...(red.otrosAsn ?? [])]) if (PROVEEDORES.has(asn)) return PROVEEDORES.get(asn);
  return null;
}
