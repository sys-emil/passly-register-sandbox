/*
 * Passly Register, Rechenkern (docs/register-spec.md, docs/plan-passly-register.md).
 *
 * Alles, was Sequencer, Browser, App und das Kommandozeilen-Werkzeug gleich
 * rechnen muessen, lebt genau hier: Leaf-Format v1, die verblindeten Tags,
 * Merkle-Hashing und Beweise nach RFC 9162, der Checkpoint-Text nach C2SP
 * tlog-checkpoint und der Lebenszyklus-Pruefer.
 *
 * Rein wie der Rest von packages/core: kein Krypto-API fest eingebaut. SHA-256
 * und HMAC gibt der Aufrufer mit (Node: node:crypto, Browser: crypto.subtle,
 * App: @noble/hashes), deshalb ist alles async. Keine Uhr und keine Zeitzone:
 * das Datum kommt als "YYYY-MM-DD" (Europe/Berlin rechnet der Aufrufer).
 */

export interface RegisterCrypto {
  sha256(data: Uint8Array): Promise<Uint8Array>;
  hmacSha256(key: Uint8Array, data: Uint8Array): Promise<Uint8Array>;
}

// ---------------------------------------------------------------- Bytes

const enc = new TextEncoder();

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

export function toHex(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += x.toString(16).padStart(2, "0");
  return s;
}

export function fromHex(h: string): Uint8Array {
  if (h.length % 2 || /[^0-9a-f]/i.test(h)) throw new Error("ungueltiges Hex");
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(2 * i, 2 * i + 2), 16);
  return out;
}

/** Index als u64 big-endian. Indizes bleiben unter 2^53. */
export function u64(n: number): Uint8Array {
  if (!Number.isSafeInteger(n) || n < 0) throw new Error(`ungueltiger Index ${n}`);
  const out = new Uint8Array(8);
  let v = n;
  for (let i = 7; i >= 0; i--) { out[i] = v % 256; v = Math.floor(v / 256); }
  return out;
}

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

export function toBase64(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i += 3) {
    const n = (b[i] << 16) | ((b[i + 1] ?? 0) << 8) | (b[i + 2] ?? 0);
    s += B64[(n >> 18) & 63] + B64[(n >> 12) & 63];
    s += i + 1 < b.length ? B64[(n >> 6) & 63] : "=";
    s += i + 2 < b.length ? B64[n & 63] : "=";
  }
  return s;
}

export function fromBase64(s: string): Uint8Array {
  if (s.length % 4 || /[^A-Za-z0-9+/=]/.test(s) || /=[^=]/.test(s)) throw new Error("ungueltiges Base64");
  const pad = s.endsWith("==") ? 2 : s.endsWith("=") ? 1 : 0;
  const out = new Uint8Array((s.length / 4) * 3 - pad);
  let o = 0;
  for (let i = 0; i < s.length; i += 4) {
    const n = [0, 1, 2, 3].reduce((acc, j) => (acc << 6) | (s[i + j] === "=" ? 0 : B64.indexOf(s[i + j])), 0);
    for (const shift of [16, 8, 0]) if (o < out.length) out[o++] = (n >> shift) & 255;
  }
  // Kanonisch: nur die eine Schreibweise ist gueltig (keine gesetzten Fuellbits).
  if (toBase64(out) !== s) throw new Error("nicht kanonisches Base64");
  return out;
}

// ---------------------------------------------------------------- Leaf v1

export const LEAF_VERSION = 1;
export const TAG_BYTES = 32;
/** version(1) | kind(1) | ticketTag(32) | nextTag(32) | eventTag(32) | holder(32) | maskedDate(4) */
export const LEAF_BYTES = 2 + 4 * TAG_BYTES + 4;

export type EntryKind = "issue" | "transfer" | "redeem" | "revoke" | "reinstate";

const KIND_CODE: Record<EntryKind, number> = { issue: 1, transfer: 2, redeem: 3, revoke: 4, reinstate: 5 };
const KIND_BY_CODE = new Map(Object.entries(KIND_CODE).map(([k, v]) => [v, k as EntryKind]));

/** Welche Felder eine Art traegt; die anderen sind Nullen (eine Kodierung pro Eintrag). */
const USES_NEXT: ReadonlySet<EntryKind> = new Set(["transfer"]);
const USES_HOLDER: ReadonlySet<EntryKind> = new Set(["issue", "transfer"]);

export interface Leaf {
  kind: EntryKind;
  ticketTag: Uint8Array;
  nextTag: Uint8Array;
  eventTag: Uint8Array;
  holder: Uint8Array;
  maskedDate: Uint8Array;
}

const ZERO_TAG = new Uint8Array(TAG_BYTES);

export function encodeLeaf(leaf: Leaf): Uint8Array {
  const fields = [leaf.ticketTag, leaf.nextTag, leaf.eventTag, leaf.holder];
  if (fields.some((f) => f.length !== TAG_BYTES) || leaf.maskedDate.length !== 4) throw new Error("falsche Feldlaenge");
  if (!USES_NEXT.has(leaf.kind) && !bytesEqual(leaf.nextTag, ZERO_TAG)) throw new Error(`${leaf.kind} traegt keinen nextTag`);
  if (!USES_HOLDER.has(leaf.kind) && !bytesEqual(leaf.holder, ZERO_TAG)) throw new Error(`${leaf.kind} traegt keinen holder`);
  return concatBytes(new Uint8Array([LEAF_VERSION, KIND_CODE[leaf.kind]]), ...fields, leaf.maskedDate);
}

export function decodeLeaf(bytes: Uint8Array): Leaf {
  if (bytes.length !== LEAF_BYTES) throw new Error(`Leaf hat ${bytes.length} statt ${LEAF_BYTES} Byte`);
  if (bytes[0] !== LEAF_VERSION) throw new Error(`unbekannte Leaf-Version ${bytes[0]}`);
  const kind = KIND_BY_CODE.get(bytes[1]);
  if (!kind) throw new Error(`unbekannte Eintragsart ${bytes[1]}`);
  const f = (n: number) => bytes.slice(2 + n * TAG_BYTES, 2 + (n + 1) * TAG_BYTES);
  const leaf: Leaf = { kind, ticketTag: f(0), nextTag: f(1), eventTag: f(2), holder: f(3), maskedDate: bytes.slice(LEAF_BYTES - 4) };
  encodeLeaf(leaf); // prueft die Null-Felder: nur die kanonische Kodierung ist gueltig
  return leaf;
}

// ---------------------------------------------------------------- Tags

const LABEL = (name: string) => enc.encode(`passly-register-v1/${name}`);
const SEP = new Uint8Array([0]);

/** Pruefcode V_t einer Inhaber-Generation aus ihrem Geheimnis K_t. */
export function viewCode(c: RegisterCrypto, ticketKey: Uint8Array): Promise<Uint8Array> {
  return c.hmacSha256(ticketKey, LABEL("view"));
}

/** Tag, unter dem ein Pruefcode den Eintrag mit Index i wiedererkennt. */
export function ticketTag(c: RegisterCrypto, view: Uint8Array, index: number): Promise<Uint8Array> {
  return c.hmacSha256(view, concatBytes(LABEL("tag"), SEP, u64(index)));
}

/** Bezug zum Event (oder Saisonpass) mit dessen Pruefschluessel K_e. */
export function eventTag(c: RegisterCrypto, scopeKey: Uint8Array, index: number): Promise<Uint8Array> {
  return c.hmacSha256(scopeKey, concatBytes(LABEL("event"), SEP, u64(index)));
}

/** Inhaber-Commitment: nur wer K_t und die Wallet kennt, kann es nachrechnen. */
export function holderTag(c: RegisterCrypto, ticketKey: Uint8Array, index: number, wallet: string): Promise<Uint8Array> {
  return c.hmacSha256(ticketKey, concatBytes(LABEL("holder"), SEP, u64(index), SEP, enc.encode(wallet)));
}

async function dateMask(c: RegisterCrypto, view: Uint8Array, index: number): Promise<Uint8Array> {
  return (await c.hmacSha256(view, concatBytes(LABEL("date"), SEP, u64(index)))).slice(0, 4);
}

// ---------------------------------------------------------------- Datum

const DAY_MS = 86_400_000;

/** "YYYY-MM-DD" -> Tage seit 1970-01-01 als u32 big-endian. */
export function encodeDay(isoDate: string): Uint8Array {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(isoDate);
  if (!m) throw new Error(`Datum ${isoDate} ist nicht YYYY-MM-DD`);
  const ms = Date.UTC(+m[1], +m[2] - 1, +m[3]);
  if (new Date(ms).toISOString().slice(0, 10) !== isoDate) throw new Error(`Datum ${isoDate} gibt es nicht`);
  const days = ms / DAY_MS;
  if (days < 0 || days > 0xffffffff) throw new Error(`Datum ${isoDate} ausserhalb des Bereichs`);
  return new Uint8Array([(days >>> 24) & 255, (days >>> 16) & 255, (days >>> 8) & 255, days & 255]);
}

export function decodeDay(b: Uint8Array): string {
  const days = ((b[0] << 24) >>> 0) + (b[1] << 16) + (b[2] << 8) + b[3];
  return new Date(days * DAY_MS).toISOString().slice(0, 10);
}

const xor4 = (a: Uint8Array, b: Uint8Array) => new Uint8Array([a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2], a[3] ^ b[3]]);

// ---------------------------------------------------------------- Eintraege bauen und lesen

export interface EntryInput {
  kind: EntryKind;
  index: number;
  /** K_t der Generation, zu der der Eintrag gehoert (bei transfer: die abgebende). */
  ticketKey: Uint8Array;
  /** Nur transfer: K_t der neuen Generation. */
  nextTicketKey?: Uint8Array;
  /** K_e des Events; Saisonpass: issue/transfer/revoke/reinstate mit dem Pass-Schluessel, redeem mit dem des Termins. */
  scopeKey: Uint8Array;
  /** issue: erster Inhaber, transfer: neuer Inhaber. */
  wallet?: string;
  /** Tag des Eintrags, Europe/Berlin. */
  date: string;
}

export async function buildLeaf(c: RegisterCrypto, e: EntryInput): Promise<Leaf> {
  if ((e.kind === "transfer") !== !!e.nextTicketKey) throw new Error("nextTicketKey gehoert genau zu transfer");
  if (USES_HOLDER.has(e.kind) !== (e.wallet !== undefined)) throw new Error(`${e.kind}: wallet ${USES_HOLDER.has(e.kind) ? "fehlt" : "gehoert nicht dazu"}`);
  const view = await viewCode(c, e.ticketKey);
  const holderKey = e.kind === "transfer" ? e.nextTicketKey! : e.ticketKey;
  return {
    kind: e.kind,
    ticketTag: await ticketTag(c, view, e.index),
    nextTag: e.nextTicketKey ? await ticketTag(c, await viewCode(c, e.nextTicketKey), e.index) : ZERO_TAG,
    eventTag: await eventTag(c, e.scopeKey, e.index),
    holder: e.wallet !== undefined ? await holderTag(c, holderKey, e.index, e.wallet) : ZERO_TAG,
    maskedDate: xor4(encodeDay(e.date), await dateMask(c, view, e.index)),
  };
}

export interface EntryView {
  kind: EntryKind;
  /**
   * "own": der Eintrag gehoert zur Generation dieses Pruefcodes.
   * "received": ein transfer, mit dem diese Generation beginnt (nextTag).
   */
  role: "own" | "received";
  /** Nur bei "own"; den Tag einer Uebergabe liest man mit dem Pruefcode davor. */
  date: string | null;
}

/** Was ein Pruefcode in einem Eintrag sieht; null, wenn der Eintrag nicht zu ihm gehoert. */
export async function readLeaf(c: RegisterCrypto, leaf: Leaf, index: number, view: Uint8Array): Promise<EntryView | null> {
  const tag = await ticketTag(c, view, index);
  if (bytesEqual(tag, leaf.ticketTag)) {
    return { kind: leaf.kind, role: "own", date: decodeDay(xor4(leaf.maskedDate, await dateMask(c, view, index))) };
  }
  if (leaf.kind === "transfer" && bytesEqual(tag, leaf.nextTag)) return { kind: leaf.kind, role: "received", date: null };
  return null;
}

/** Eingeloggt: steht in diesem Eintrag die eigene Wallet als Inhaber? */
export async function holderMatches(c: RegisterCrypto, leaf: Leaf, index: number, ticketKey: Uint8Array, wallet: string): Promise<boolean> {
  if (!USES_HOLDER.has(leaf.kind)) return false;
  return bytesEqual(await holderTag(c, ticketKey, index, wallet), leaf.holder);
}

export interface ScopeTally { issued: number; transferred: number; redeemed: number; revoked: number; reinstated: number }

/** Nachzaehlen mit dem Pruefschluessel: welche Eintraege gehoeren zu diesem Event? */
export async function tallyScope(c: RegisterCrypto, entries: { index: number; leaf: Leaf }[], scopeKey: Uint8Array): Promise<ScopeTally> {
  const t: ScopeTally = { issued: 0, transferred: 0, redeemed: 0, revoked: 0, reinstated: 0 };
  const field: Record<EntryKind, keyof ScopeTally> = { issue: "issued", transfer: "transferred", redeem: "redeemed", revoke: "revoked", reinstate: "reinstated" };
  for (const { index, leaf } of entries) {
    if (bytesEqual(await eventTag(c, scopeKey, index), leaf.eventTag)) t[field[leaf.kind]]++;
  }
  return t;
}

// ---------------------------------------------------------------- Merkle (RFC 9162, Abschnitt 2.1)

export function leafHash(c: RegisterCrypto, leafBytes: Uint8Array): Promise<Uint8Array> {
  return c.sha256(concatBytes(new Uint8Array([0x00]), leafBytes));
}

export function nodeHash(c: RegisterCrypto, left: Uint8Array, right: Uint8Array): Promise<Uint8Array> {
  return c.sha256(concatBytes(new Uint8Array([0x01]), left, right));
}

/** Groesste Zweierpotenz echt kleiner als n (n >= 2). */
function splitPoint(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

/** MTH ueber bereits gehashte Blaetter. Leerer Baum: SHA-256 der leeren Eingabe. */
export async function rootHash(c: RegisterCrypto, leafHashes: Uint8Array[]): Promise<Uint8Array> {
  const n = leafHashes.length;
  if (n === 0) return c.sha256(new Uint8Array(0));
  if (n === 1) return leafHashes[0];
  const k = splitPoint(n);
  return nodeHash(c, await rootHash(c, leafHashes.slice(0, k)), await rootHash(c, leafHashes.slice(k)));
}

/**
 * Hash des Teilbaums ueber die Blaetter [start, end). Die Beweise rechnen nur
 * damit, egal ob die Hashes aus einer Liste kommen oder aus Kacheln.
 */
export type RangeHash = (start: number, end: number) => Promise<Uint8Array>;

function listRangeHash(c: RegisterCrypto, leafHashes: Uint8Array[]): RangeHash {
  return (start, end) => rootHash(c, leafHashes.slice(start, end));
}

/** Inklusionsbeweis PATH(m, D[n]) aus RFC 9162 2.1.3.1. */
export async function inclusionProof(c: RegisterCrypto, index: number, leafHashes: Uint8Array[]): Promise<Uint8Array[]> {
  return inclusionProofFrom(index, leafHashes.length, listRangeHash(c, leafHashes));
}

export async function inclusionProofFrom(index: number, size: number, h: RangeHash): Promise<Uint8Array[]> {
  if (!Number.isSafeInteger(index) || index < 0 || index >= size) throw new Error(`Index ${index} nicht im Baum der Groesse ${size}`);
  const path = async (m: number, start: number, end: number): Promise<Uint8Array[]> => {
    if (end - start === 1) return [];
    const k = splitPoint(end - start);
    return m < k
      ? [...(await path(m, start, start + k)), await h(start + k, end)]
      : [...(await path(m - k, start + k, end)), await h(start, start + k)];
  };
  return path(index, 0, size);
}

/** Pruefung nach RFC 9162 2.1.3.2. */
export async function verifyInclusion(
  c: RegisterCrypto,
  p: { index: number; size: number; leafHash: Uint8Array; proof: Uint8Array[]; root: Uint8Array },
): Promise<boolean> {
  if (!Number.isSafeInteger(p.index) || !Number.isSafeInteger(p.size) || p.index < 0 || p.index >= p.size) return false;
  let fn = p.index;
  let sn = p.size - 1;
  let r = p.leafHash;
  for (const h of p.proof) {
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      r = await nodeHash(c, h, r);
      while (fn % 2 === 0 && fn !== 0) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2); }
    } else {
      r = await nodeHash(c, r, h);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  return sn === 0 && bytesEqual(r, p.root);
}

/** Konsistenzbeweis PROOF(m, D[n]) aus RFC 9162 2.1.4.1. */
export async function consistencyProof(c: RegisterCrypto, m: number, leafHashes: Uint8Array[]): Promise<Uint8Array[]> {
  return consistencyProofFrom(m, leafHashes.length, listRangeHash(c, leafHashes));
}

export async function consistencyProofFrom(m: number, n: number, h: RangeHash): Promise<Uint8Array[]> {
  if (!Number.isSafeInteger(m) || !Number.isSafeInteger(n) || m < 1 || m > n) throw new Error(`Konsistenz von ${m} nach ${n} nicht definiert`);
  const sub = async (m: number, start: number, end: number, b: boolean): Promise<Uint8Array[]> => {
    if (m === end - start) return b ? [] : [await h(start, end)];
    const k = splitPoint(end - start);
    return m <= k
      ? [...(await sub(m, start, start + k, b)), await h(start + k, end)]
      : [...(await sub(m - k, start + k, end, false)), await h(start, start + k)];
  };
  return sub(m, 0, n, true);
}

/** Pruefung nach RFC 9162 2.1.4.2: der Baum der Groesse n ist eine Fortsetzung dessen der Groesse m. */
export async function verifyConsistency(
  c: RegisterCrypto,
  p: { m: number; n: number; rootM: Uint8Array; rootN: Uint8Array; proof: Uint8Array[] },
): Promise<boolean> {
  const { m, n } = p;
  if (!Number.isSafeInteger(m) || !Number.isSafeInteger(n) || m < 1 || m > n) return false;
  if (m === n) return p.proof.length === 0 && bytesEqual(p.rootM, p.rootN);
  if (p.proof.length === 0) return false;
  const path = (m & (m - 1)) === 0 ? [p.rootM, ...p.proof] : p.proof;
  let fn = m - 1;
  let sn = n - 1;
  while (fn % 2 === 1) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2); }
  let fr = path[0];
  let sr = path[0];
  for (const h of path.slice(1)) {
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      fr = await nodeHash(c, h, fr);
      sr = await nodeHash(c, h, sr);
      while (fn % 2 === 0 && fn !== 0) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2); }
    } else {
      sr = await nodeHash(c, sr, h);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  return sn === 0 && bytesEqual(fr, p.rootM) && bytesEqual(sr, p.rootN);
}

// ---------------------------------------------------------------- Rechter Rand (Compact Range)

/**
 * Die Wurzeln der vollstaendigen Teilbaeume am rechten Rand, groesster zuerst:
 * einer pro gesetztem Bit der Baumgroesse. Damit haengt der Sequencer Eintraege
 * an und rechnet die Wurzel, ohne je den ganzen Baum zu laden.
 */
export async function frontierAppend(c: RegisterCrypto, frontier: Uint8Array[], size: number, leaf: Uint8Array): Promise<Uint8Array[]> {
  if (frontier.length !== popcount(size)) throw new Error(`Rand passt nicht zur Groesse ${size}`);
  const out = [...frontier, leaf];
  for (let s = size; s % 2 === 1; s = Math.floor(s / 2)) {
    const right = out.pop()!;
    const left = out.pop()!;
    out.push(await nodeHash(c, left, right));
  }
  return out;
}

export async function frontierRoot(c: RegisterCrypto, frontier: Uint8Array[]): Promise<Uint8Array> {
  if (frontier.length === 0) return c.sha256(new Uint8Array(0));
  let r = frontier[frontier.length - 1];
  for (let i = frontier.length - 2; i >= 0; i--) r = await nodeHash(c, frontier[i], r);
  return r;
}

function popcount(n: number): number {
  let k = 0;
  for (let v = n; v > 0; v = Math.floor(v / 2)) k += v % 2;
  return k;
}

// ---------------------------------------------------------------- Kacheln (C2SP tlog-tiles)

/*
 * Der Baum wird als statische Dateien veroeffentlicht, aus denen jeder jeden
 * Beweis selbst rechnet. Eine Kachel der Ebene L haelt bis zu 256 Hashes der
 * Baumhoehe 8·L: Ebene 0 die Blatt-Hashes, Ebene 1 die Wurzeln je 256 Blaetter
 * usw. Eine unvollstaendige Kachel traegt ihre Breite im Pfad (".p/W"), damit
 * ist jeder Pfad ausser "checkpoint" unveraenderlich.
 */

export const TILE_HEIGHT = 8;
export const TILE_WIDTH = 2 ** TILE_HEIGHT;

export interface TileRef { level: number; index: number; width: number }

/** Index als Pfad: Dreiergruppen, alle ausser der letzten mit "x". 1234067 → "x001/x234/067". */
export function tileIndexPath(index: number): string {
  if (!Number.isSafeInteger(index) || index < 0) throw new Error(`ungueltiger Kachelindex ${index}`);
  let n = index;
  let path = String(n % 1000).padStart(3, "0");
  for (n = Math.floor(n / 1000); n > 0; n = Math.floor(n / 1000)) path = `x${String(n % 1000).padStart(3, "0")}/${path}`;
  return path;
}

function widthSuffix(width: number): string {
  if (!Number.isInteger(width) || width < 1 || width > TILE_WIDTH) throw new Error(`ungueltige Kachelbreite ${width}`);
  return width === TILE_WIDTH ? "" : `.p/${width}`;
}

/** "tile/<L>/<N>[.p/<W>]" */
export function tilePath(t: TileRef): string {
  return `tile/${t.level}/${tileIndexPath(t.index)}${widthSuffix(t.width)}`;
}

/** "tile/entries/<N>[.p/<W>]": die Eintraege zur Kachel der Ebene 0 mit gleichem Index. */
export function entryBundlePath(index: number, width: number): string {
  return `tile/entries/${tileIndexPath(index)}${widthSuffix(width)}`;
}

/** Zahl der vollstaendigen Knoten der Hoehe 8·level in einem Baum dieser Groesse. */
function nodesAt(size: number, level: number): number {
  return Math.floor(size / TILE_WIDTH ** level);
}

/** Breite der Kachel (level, index) bei dieser Baumgroesse, 0 wenn es sie noch nicht gibt. */
export function tileWidthAt(size: number, level: number, index: number): number {
  return Math.max(0, Math.min(TILE_WIDTH, nodesAt(size, level) - index * TILE_WIDTH));
}

/** Kacheln, die beim Wachsen von oldSize auf newSize neu entstehen (aller Ebenen, unten zuerst). */
export function tileRefs(oldSize: number, newSize: number): TileRef[] {
  if (!(0 <= oldSize && oldSize <= newSize)) throw new Error(`Kacheln von ${oldSize} nach ${newSize} nicht definiert`);
  const out: TileRef[] = [];
  for (let level = 0; nodesAt(newSize, level) > 0; level++) {
    const count = nodesAt(newSize, level);
    for (let index = Math.floor(nodesAt(oldSize, level) / TILE_WIDTH); index * TILE_WIDTH < count; index++) {
      const width = tileWidthAt(newSize, level, index);
      if (width !== tileWidthAt(oldSize, level, index)) out.push({ level, index, width });
    }
  }
  return out;
}

/**
 * Welche schon vorhandenen Knoten der Ebenen ≥ 1 buildTiles braucht: je Ebene
 * die vor oldSize fertigen Knoten der Kachel, die gerade waechst (hoechstens 255).
 */
export function tileNodeRanges(oldSize: number, newSize: number): { level: number; from: number; to: number }[] {
  const out: { level: number; from: number; to: number }[] = [];
  for (let level = 1; nodesAt(newSize, level) > 0; level++) {
    const to = nodesAt(oldSize, level);
    out.push({ level, from: Math.floor(to / TILE_WIDTH) * TILE_WIDTH, to });
  }
  return out;
}

/** Erster Blatt-Index, dessen Hash buildTiles braucht. */
export function tileLeafStart(oldSize: number): number {
  return Math.floor(oldSize / TILE_WIDTH) * TILE_WIDTH;
}

/**
 * Rechnet die Kacheln fuer das Wachstum oldSize → newSize.
 * leafHashes: Blatt-Hashes ab tileLeafStart(oldSize) bis newSize.
 * oldNodes: je Ebene ≥ 1 die Knoten aus tileNodeRanges, in Reihenfolge.
 * Zurueck kommen die Kacheln und die neu fertigen Knoten der Ebenen ≥ 1.
 */
export async function buildTiles(
  c: RegisterCrypto,
  oldSize: number,
  newSize: number,
  leafHashes: Uint8Array[],
  oldNodes: Map<number, Uint8Array[]>,
): Promise<{ tiles: { ref: TileRef; data: Uint8Array }[]; nodes: { level: number; index: number; hash: Uint8Array }[] }> {
  const start = tileLeafStart(oldSize);
  if (leafHashes.length !== newSize - start) throw new Error(`erwartet ${newSize - start} Blatt-Hashes ab ${start}, bekommen ${leafHashes.length}`);
  const levels: { from: number; hashes: Uint8Array[] }[] = [{ from: start, hashes: leafHashes }];
  const nodes: { level: number; index: number; hash: Uint8Array }[] = [];

  for (const { level, from, to } of tileNodeRanges(oldSize, newSize)) {
    const old = oldNodes.get(level) ?? [];
    if (old.length !== to - from) throw new Error(`Ebene ${level}: erwartet ${to - from} Knoten ab ${from}, bekommen ${old.length}`);
    const below = levels[level - 1];
    const hashes = [...old];
    for (let k = to; k < nodesAt(newSize, level); k++) {
      const first = k * TILE_WIDTH - below.from;
      const hash = await rootHash(c, below.hashes.slice(first, first + TILE_WIDTH));
      hashes.push(hash);
      nodes.push({ level, index: k, hash });
    }
    levels.push({ from, hashes });
  }

  const tiles = tileRefs(oldSize, newSize).map((ref) => {
    const l = levels[ref.level];
    const first = ref.index * TILE_WIDTH - l.from;
    return { ref, data: concatBytes(...l.hashes.slice(first, first + ref.width)) };
  });
  return { tiles, nodes };
}

/** Eintragsbuendel: je Eintrag Laenge als u16 big-endian, dann die Bytes. */
export function encodeEntryBundle(entries: Uint8Array[]): Uint8Array {
  return concatBytes(...entries.flatMap((e) => {
    if (e.length > 0xffff) throw new Error("Eintrag zu lang fuer ein Buendel");
    return [new Uint8Array([e.length >> 8, e.length & 0xff]), e];
  }));
}

export function decodeEntryBundle(b: Uint8Array): Uint8Array[] {
  const out: Uint8Array[] = [];
  for (let i = 0; i < b.length;) {
    if (i + 2 > b.length) throw new Error("Buendel endet mitten in einer Laenge");
    const n = (b[i] << 8) | b[i + 1];
    if (i + 2 + n > b.length) throw new Error("Buendel endet mitten in einem Eintrag");
    out.push(b.slice(i + 2, i + 2 + n));
    i += 2 + n;
  }
  return out;
}

/**
 * Hash-Quelle aus Kacheln fuer einen Baum der Groesse `size` (aus einem
 * signierten Checkpoint). readTile laedt eine Kachel genau in der Breite, die
 * sie bei dieser Groesse hat; jede wird nur einmal geladen.
 */
export function tileRangeHash(c: RegisterCrypto, size: number, readTile: (ref: TileRef) => Promise<Uint8Array>): RangeHash {
  const cache = new Map<string, Promise<Uint8Array>>();
  const tile = (ref: TileRef) => {
    const key = tilePath(ref);
    let p = cache.get(key);
    if (!p) {
      p = readTile(ref).then((d) => {
        if (d.length !== ref.width * 32) throw new Error(`Kachel ${key} hat ${d.length} statt ${ref.width * 32} Byte`);
        return d;
      });
      cache.set(key, p);
    }
    return p;
  };
  const node = async (height: number, k: number): Promise<Uint8Array> => {
    if (height % TILE_HEIGHT === 0) {
      const level = height / TILE_HEIGHT;
      const index = Math.floor(k / TILE_WIDTH);
      const width = tileWidthAt(size, level, index);
      const slot = k % TILE_WIDTH;
      if (slot >= width) throw new Error(`Knoten ${height}/${k} gibt es bei Groesse ${size} nicht`);
      return (await tile({ level, index, width })).slice(slot * 32, slot * 32 + 32);
    }
    return nodeHash(c, await node(height - 1, 2 * k), await node(height - 1, 2 * k + 1));
  };
  const range: RangeHash = async (start, end) => {
    if (!(0 <= start && start < end && end <= size)) throw new Error(`Bereich ${start}..${end} nicht im Baum der Groesse ${size}`);
    const n = end - start;
    if ((n & (n - 1)) === 0 && start % n === 0) return node(Math.log2(n), start / n);
    const k = splitPoint(n);
    return nodeHash(c, await range(start, start + k), await range(start + k, end));
  };
  return range;
}

/** Wurzel aus Kacheln; muss der Wurzel des Checkpoints gleicher Groesse entsprechen. */
export async function tileRoot(c: RegisterCrypto, size: number, readTile: (ref: TileRef) => Promise<Uint8Array>): Promise<Uint8Array> {
  return size === 0 ? c.sha256(new Uint8Array(0)) : tileRangeHash(c, size, readTile)(0, size);
}

// ---------------------------------------------------------------- Checkpoint (C2SP tlog-checkpoint)

export const REGISTER_ORIGIN = "getpassly.de/register";

export interface Checkpoint { origin: string; size: number; root: Uint8Array; extensions: string[] }

/** Der signierte Text: Herkunft, Groesse, Wurzel in Base64, je eine Zeile, abschliessender Umbruch. */
export function formatCheckpoint(cp: Checkpoint): string {
  if (!cp.origin || /\n/.test(cp.origin)) throw new Error("ungueltige Herkunft");
  if (!Number.isSafeInteger(cp.size) || cp.size < 0) throw new Error("ungueltige Groesse");
  if (cp.root.length !== 32) throw new Error("Wurzel muss 32 Byte haben");
  if (cp.extensions.some((l) => !l || /\n/.test(l))) throw new Error("ungueltige Zusatzzeile");
  return [cp.origin, String(cp.size), toBase64(cp.root), ...cp.extensions].join("\n") + "\n";
}

export function parseCheckpoint(text: string): Checkpoint {
  if (!text.endsWith("\n")) throw new Error("Checkpoint endet nicht mit Zeilenumbruch");
  const lines = text.slice(0, -1).split("\n");
  if (lines.length < 3) throw new Error("Checkpoint zu kurz");
  const [origin, size, root, ...extensions] = lines;
  if (!/^(0|[1-9][0-9]*)$/.test(size) || !Number.isSafeInteger(+size)) throw new Error("ungueltige Groesse");
  const cp = { origin, size: +size, root: fromBase64(root), extensions };
  if (formatCheckpoint(cp) !== text) throw new Error("Checkpoint nicht kanonisch");
  return cp;
}

// ---------------------------------------------------------------- Signierte Notiz (C2SP signed-note)

/** Ed25519 pruefen; wie in door.ts gibt der Aufrufer die Implementierung mit. */
export type Ed25519Verify = (publicKey: Uint8Array, signature: Uint8Array, message: Uint8Array) => Promise<boolean>;

const ALG_ED25519 = 0x01;

function checkKeyName(name: string): void {
  if (!name || /[\s+]/.test(name)) throw new Error(`ungueltiger Schluesselname ${name}`);
}

/** Erste 4 Byte von SHA-256(name || "\n" || 0x01 || publicKey). */
export async function noteKeyHash(c: RegisterCrypto, name: string, publicKey: Uint8Array): Promise<Uint8Array> {
  checkKeyName(name);
  return (await c.sha256(concatBytes(enc.encode(`${name}\n`), new Uint8Array([ALG_ED25519]), publicKey))).slice(0, 4);
}

/** Pruefschluessel im Format von golang.org/x/mod/sumdb/note: name+hash+base64(0x01||key). */
export async function formatVerifierKey(c: RegisterCrypto, name: string, publicKey: Uint8Array): Promise<string> {
  return `${name}+${toHex(await noteKeyHash(c, name, publicKey))}+${toBase64(concatBytes(new Uint8Array([ALG_ED25519]), publicKey))}`;
}

export interface VerifierKey { name: string; keyHash: Uint8Array; publicKey: Uint8Array }

export async function parseVerifierKey(c: RegisterCrypto, vkey: string): Promise<VerifierKey> {
  // Nur an den ersten zwei "+" teilen: Base64 darf selbst "+" enthalten (wie Go).
  const a = vkey.indexOf("+");
  const b = vkey.indexOf("+", a + 1);
  if (a < 1 || b < 0) throw new Error("ungueltiger Pruefschluessel");
  const name = vkey.slice(0, a);
  const hash = vkey.slice(a + 1, b);
  const key = vkey.slice(b + 1);
  if (!/^[0-9a-f]{8}$/.test(hash)) throw new Error("ungueltiger Pruefschluessel");
  const raw = fromBase64(key);
  if (raw.length !== 33 || raw[0] !== ALG_ED25519) throw new Error("nur Ed25519-Schluessel");
  const publicKey = raw.slice(1);
  if (toHex(await noteKeyHash(c, name, publicKey)) !== hash) throw new Error("Schluessel-Hash passt nicht");
  return { name, keyHash: fromHex(hash), publicKey };
}

export interface NoteSignature { name: string; keyHash: Uint8Array; signature: Uint8Array }

/** Text (endet mit \n), Leerzeile, je Signatur eine Zeile "— name base64(hash||sig)". */
export function formatSignedNote(text: string, signatures: NoteSignature[]): string {
  if (!text.endsWith("\n") || text.includes("\n\n")) throw new Error("Notiztext muss mit genau einem Umbruch enden");
  if (signatures.length === 0) throw new Error("Notiz ohne Signatur");
  return text + "\n" + signatures.map((s) => {
    checkKeyName(s.name);
    return `— ${s.name} ${toBase64(concatBytes(s.keyHash, s.signature))}\n`;
  }).join("");
}

export function parseSignedNote(note: string): { text: string; signatures: NoteSignature[] } {
  const split = note.lastIndexOf("\n\n");
  if (split < 0) throw new Error("Notiz ohne Signaturblock");
  const text = note.slice(0, split + 1);
  const block = note.slice(split + 2);
  if (!block.endsWith("\n")) throw new Error("Signaturblock endet nicht mit Umbruch");
  const signatures = block.slice(0, -1).split("\n").map((line) => {
    const m = /^— (\S+) (\S+)$/.exec(line);
    if (!m) throw new Error(`ungueltige Signaturzeile: ${line}`);
    const raw = fromBase64(m[2]);
    if (raw.length < 5) throw new Error("Signatur zu kurz");
    return { name: m[1], keyHash: raw.slice(0, 4), signature: raw.slice(4) };
  });
  return { text, signatures };
}

/** Gilt die Notiz mit diesem Schluessel? Fremde Signaturen (Zeugen) werden uebersprungen. */
export async function verifySignedNote(note: string, key: VerifierKey, verify: Ed25519Verify): Promise<string | null> {
  const { text, signatures } = parseSignedNote(note);
  for (const s of signatures) {
    if (s.name !== key.name || !bytesEqual(s.keyHash, key.keyHash)) continue;
    if (s.signature.length === 64 && (await verify(key.publicKey, s.signature, enc.encode(text)))) return text;
  }
  return null;
}

// ---------------------------------------------------------------- Lebenszyklus

export type TicketStatus = "valid" | "redeemed" | "revoked";

export interface LifecycleStep {
  index: number;
  kind: EntryKind;
  /** Nur redeem eines Saisonpasses: welcher Termin (z. B. der eventTag), damit pro Termin einmal gilt. */
  occasion?: string;
}

export interface LifecycleResult { status: TicketStatus | null; generations: number; problems: string[] }

/**
 * Spielt den Verlauf eines Tickets (alle Generationen, aufsteigend nach Index)
 * nach und meldet jeden Schritt, den Passly so nie schreiben duerfte.
 */
export function replayLifecycle(steps: LifecycleStep[], opts: { pass?: boolean } = {}): LifecycleResult {
  const problems: string[] = [];
  let issued = false;
  let revoked = false;
  let redeemed = false;
  let generations = 0;
  const occasions = new Set<string>();
  let last = -1;
  for (const s of steps) {
    const at = `#${s.index} ${s.kind}`;
    if (s.index <= last) problems.push(`${at}: Reihenfolge`);
    last = Math.max(last, s.index);
    if (s.kind === "issue") {
      if (issued) problems.push(`${at}: zweite Ausstellung`);
      issued = true;
      generations = Math.max(generations, 1);
      continue;
    }
    if (!issued) { problems.push(`${at}: vor der Ausstellung`); continue; }
    switch (s.kind) {
      case "transfer":
        // Ein eingeloestes Ticket darf den Inhaber wechseln (Abendkasse: sofort
        // eingelassen, danach per Mail-Link ins Konto geholt). Es bleibt
        // eingeloest; ein zweiter Einlass ist weiter ungueltig.
        if (revoked) problems.push(`${at}: widerrufenes Ticket weitergegeben`);
        generations++;
        break;
      case "redeem":
        if (revoked) problems.push(`${at}: Einlass nach Widerruf`);
        else if (opts.pass) {
          const o = s.occasion ?? "";
          if (!o) problems.push(`${at}: Termin fehlt`);
          else if (occasions.has(o)) problems.push(`${at}: zweiter Einlass am selben Termin`);
          occasions.add(o);
        } else if (redeemed) problems.push(`${at}: zweiter Einlass`);
        redeemed = true;
        break;
      case "revoke":
        if (revoked) problems.push(`${at}: schon widerrufen`);
        revoked = true;
        break;
      case "reinstate":
        if (!revoked) problems.push(`${at}: nichts zurückzunehmen`);
        revoked = false;
        break;
    }
  }
  const status: TicketStatus | null = !issued ? null : revoked ? "revoked" : redeemed && !opts.pass ? "redeemed" : "valid";
  return { status, generations, problems };
}

// ---------------------------------------------------------------- Ticket pruefen (Browser, App)

/** Laedt eine oeffentliche Datei des Registers (checkpoint, tile/...) als Bytes. */
export type RegisterFiles = (path: string) => Promise<Uint8Array>;

export interface CheckedEntry {
  index: number;
  kind: EntryKind;
  role: "own" | "received";
  date: string | null;
  /** Diese Generation steht hier als Inhaber (nur mit ticketKey + wallet geprueft). */
  holderIsYou: boolean;
}

export interface TicketCheck {
  checkpoint: Checkpoint;
  entries: CheckedEntry[];
  lifecycle: LifecycleResult;
  /** Indizes, die der Server nannte, die aber noch nicht im signierten Stand sind. */
  pending: number[];
  /** Die letzte (gefragte) Generation hat das Ticket weitergegeben: ihr Pruefcode ist veraltet. */
  handedOn: boolean;
  /** Beweisweg des neuesten Eintrags, zum Zeichnen: Blatt-Hash und Geschwister bis zur Wurzel. */
  path: { index: number; leafHash: Uint8Array; proof: Uint8Array[] } | null;
}

export interface TicketGeneration {
  view: Uint8Array;
  /** Vom Server genannte Eintraege; jeder wird hier gegen den Pruefcode nachgerechnet. */
  indices: number[];
  /** Nur die eigene, aktuelle Generation: K_t fuer die Inhaber-Pruefung. */
  ticketKey?: Uint8Array;
}

/**
 * Prueft ein Ticket allein aus den oeffentlichen Dateien: Unterschrift des
 * Checkpoints, Kacheln gegen seine Wurzel, jeder genannte Eintrag per
 * Inklusionsbeweis und gegen den Pruefcode, danach der Lebenszyklus.
 * Wirft mit einer lesbaren Meldung, sobald etwas nicht stimmt.
 *
 * Vollstaendigkeit beweist das nicht: verschweigt der Server einen Eintrag,
 * faellt das erst dem Monitor auf, der das ganze Register liest (Stufe 5).
 */
export async function checkTicket(
  c: RegisterCrypto,
  verify: Ed25519Verify,
  key: VerifierKey,
  files: RegisterFiles,
  generations: TicketGeneration[],
  opts: { wallet?: string; pass?: boolean } = {},
): Promise<TicketCheck> {
  const text = await verifySignedNote(new TextDecoder().decode(await files("checkpoint")), key, verify);
  if (!text) throw new Error("Die Unterschrift des Registers stimmt nicht.");
  const checkpoint = parseCheckpoint(text);
  if (checkpoint.origin !== key.name) throw new Error("Der Stand gehört zu einem anderen Register.");
  const size = checkpoint.size;
  const h = tileRangeHash(c, size, (ref) => files(tilePath(ref)));
  if (size > 0 && !bytesEqual(await h(0, size), checkpoint.root)) throw new Error("Die Dateien passen nicht zum unterschriebenen Stand.");

  const bundles = new Map<number, Promise<Uint8Array[]>>();
  const leafAt = async (i: number) => {
    const n = Math.floor(i / TILE_WIDTH);
    let b = bundles.get(n);
    if (!b) {
      b = files(entryBundlePath(n, Math.min(TILE_WIDTH, size - n * TILE_WIDTH))).then(decodeEntryBundle);
      bundles.set(n, b);
    }
    const leaves = await b;
    const bytes = leaves[i % TILE_WIDTH];
    if (!bytes) throw new Error(`Eintrag ${i} fehlt in den Dateien.`);
    return bytes;
  };

  const byIndex = new Map<number, CheckedEntry & { leafHash: Uint8Array }>();
  const pending: number[] = [];
  let handedOn = false;
  for (const g of generations) {
    for (const i of g.indices) {
      if (i >= size) { pending.push(i); continue; }
      const bytes = await leafAt(i);
      const leaf = decodeLeaf(bytes);
      const seen = await readLeaf(c, leaf, i, g.view);
      if (!seen) throw new Error(`Eintrag ${i} gehört nicht zu diesem Prüfcode.`);
      if (g === generations.at(-1) && seen.kind === "transfer" && seen.role === "own") handedOn = true;
      const lh = await leafHash(c, bytes);
      if (!(await verifyInclusion(c, { index: i, size, leafHash: lh, proof: await inclusionProofFrom(i, size, h), root: checkpoint.root }))) {
        throw new Error(`Eintrag ${i} steht nicht im unterschriebenen Stand.`);
      }
      const holderIsYou = !!(g.ticketKey && opts.wallet) && await holderMatches(c, leaf, i, g.ticketKey, opts.wallet);
      const prev = byIndex.get(i);
      // Eine Weitergabe sieht der alte Code als "own" (mit Datum), der neue als "received".
      if (!prev || (prev.role === "received" && seen.role === "own")) {
        byIndex.set(i, { index: i, ...seen, holderIsYou: holderIsYou || !!prev?.holderIsYou, leafHash: lh });
      } else if (holderIsYou) prev.holderIsYou = true;
    }
  }

  const sorted = [...byIndex.values()].sort((a, b) => a.index - b.index);
  const lifecycle = replayLifecycle(sorted.map((e) => ({ index: e.index, kind: e.kind, occasion: opts.pass && e.kind === "redeem" ? `#${e.index}` : undefined })), { pass: opts.pass });
  const last = sorted.at(-1);
  const path = last ? { index: last.index, leafHash: last.leafHash, proof: await inclusionProofFrom(last.index, size, h) } : null;
  return { checkpoint, entries: sorted.map(({ index, kind, role, date, holderIsYou }) => ({ index, kind, role, date, holderIsYou })), lifecycle, pending, handedOn, path };
}

// ---------------------------------------------------------------- Ganzes Register lesen (Nachzaehlen, Waechter)

/** Checkpoint laden, Unterschrift und Herkunft pruefen. */
export async function readCheckpoint(
  verify: Ed25519Verify, key: VerifierKey, files: RegisterFiles,
): Promise<{ checkpoint: Checkpoint; note: string }> {
  const note = new TextDecoder().decode(await files("checkpoint"));
  const text = await verifySignedNote(note, key, verify);
  if (!text) throw new Error("Die Unterschrift des Registers stimmt nicht.");
  const checkpoint = parseCheckpoint(text);
  if (checkpoint.origin !== key.name) throw new Error("Der Stand gehört zu einem anderen Register.");
  return { checkpoint, note };
}

/**
 * Liest ALLE Eintraege 0..size-1 aus den Eintragsbuendeln, prueft jeden auf
 * gueltige Kodierung und rechnet aus ihren Blatt-Hashes die Wurzel neu. Nur
 * wenn sie `root` gleicht, ist bewiesen, dass genau diese Eintraege (keiner
 * mehr, keiner weniger, keiner veraendert) im unterschriebenen Stand stehen.
 * `visit` sieht jeden Eintrag, aber gilt erst nach erfolgreichem Ende.
 */
export async function readAllEntries(
  c: RegisterCrypto,
  cp: { size: number; root: Uint8Array },
  files: RegisterFiles,
  visit?: (index: number, leaf: Leaf, hash: Uint8Array) => void | Promise<void>,
  onProgress?: (done: number, size: number) => void,
): Promise<void> {
  const { size } = cp;
  let frontier: Uint8Array[] = [];
  onProgress?.(0, size);
  // Buendel einzeln laden und rechnen, das naechste schon im Voraus holen.
  const bundle = (n: number) => files(entryBundlePath(n, Math.min(TILE_WIDTH, size - n * TILE_WIDTH))).then(decodeEntryBundle);
  let next = size > 0 ? bundle(0) : null;
  for (let n = 0; n * TILE_WIDTH < size; n++) {
    const leaves = await next!;
    next = (n + 1) * TILE_WIDTH < size ? bundle(n + 1) : null;
    const width = Math.min(TILE_WIDTH, size - n * TILE_WIDTH);
    if (leaves.length !== width) throw new Error(`In den Dateien fehlen Einträge (Bündel ${n}).`);
    const start = n * TILE_WIDTH;
    const rows = await Promise.all(leaves.map(async (bytes, j) => {
      let leaf: Leaf;
      try { leaf = decodeLeaf(bytes); } catch (e) { throw new Error(`Eintrag ${start + j} ist ungültig: ${e instanceof Error ? e.message : e}`); }
      return { leaf, hash: await leafHash(c, bytes) };
    }));
    for (let j = 0; j < rows.length; j++) {
      frontier = await frontierAppend(c, frontier, start + j, rows[j].hash);
      await visit?.(start + j, rows[j].leaf, rows[j].hash);
    }
    onProgress?.(start + width, size);
  }
  if (!bytesEqual(await frontierRoot(c, frontier), cp.root)) {
    throw new Error("Die Einträge passen nicht zum unterschriebenen Stand. Es fehlt etwas oder wurde verändert.");
  }
}

// ---------------------------------------------------------------- Event nachzaehlen (Dashboard, Kassenpruefer)

export interface ScopeCount {
  checkpoint: Checkpoint;
  /** Der unterschriebene Stand als Text, zum Aufheben (spaeter Konsistenz pruefen). */
  note: string;
  tally: ScopeTally;
}

/**
 * Zaehlt die Eintraege eines Events (oder Saisonpasses) mit dessen
 * Pruefschluessel K_e, allein aus den oeffentlichen Dateien (readAllEntries).
 * Anders als checkTicket beweist das Vollstaendigkeit: ein verschwiegener,
 * veraenderter oder eingeschobener Eintrag aendert die Wurzel.
 */
export async function countScope(
  c: RegisterCrypto,
  verify: Ed25519Verify,
  key: VerifierKey,
  files: RegisterFiles,
  scopeKey: Uint8Array,
  onProgress?: (done: number, size: number) => void,
): Promise<ScopeCount> {
  const { checkpoint, note } = await readCheckpoint(verify, key, files);
  const tally: ScopeTally = { issued: 0, transferred: 0, redeemed: 0, revoked: 0, reinstated: 0 };
  const field: Record<EntryKind, keyof ScopeTally> = { issue: "issued", transfer: "transferred", redeem: "redeemed", revoke: "revoked", reinstate: "reinstated" };
  const mine: { index: number; leaf: Leaf }[] = [];
  await readAllEntries(c, checkpoint, files, (index, leaf) => { mine.push({ index, leaf }); }, onProgress);
  // HMACs erst nach dem Lesen, parallel: der Rand oben muss der Reihe nach laufen, das hier nicht.
  const hits = await Promise.all(mine.map(async ({ index, leaf }) => bytesEqual(await eventTag(c, scopeKey, index), leaf.eventTag)));
  hits.forEach((hit, i) => { if (hit) tally[field[mine[i].leaf.kind]]++; });
  return { checkpoint, note, tally };
}

// ---------------------------------------------------------------- Waechter (Monitor, Git-Verankerung)

export interface WatchResult {
  checkpoint: Checkpoint;
  note: string;
  /** Wie viele Eintraege seit dem vorigen Stand dazukamen (ohne vorigen Stand: alle). */
  added: number;
  kinds: Record<EntryKind, number>;
}

/**
 * Was der Waechter (stuendlich, ausserhalb von Passly) prueft: Unterschrift des
 * neuesten Stands; falls ein voriger Stand bekannt ist, dass der neue ihn
 * fortsetzt (Konsistenzbeweis aus den Kacheln, RFC 9162 2.1.4) und der vorige
 * selbst gueltig unterschrieben war; mit `full` zusaetzlich jeden Eintrag
 * (readAllEntries) und jede Kachel dieses Stands. Wirft bei jedem Bruch mit lesbarer Meldung.
 */
export async function watchRegister(
  c: RegisterCrypto,
  verify: Ed25519Verify,
  key: VerifierKey,
  files: RegisterFiles,
  opts: { previousNote?: string; full?: boolean; onProgress?: (done: number, size: number) => void } = {},
): Promise<WatchResult> {
  const { checkpoint, note } = await readCheckpoint(verify, key, files);
  const size = checkpoint.size;
  const h = tileRangeHash(c, size, (ref) => files(tilePath(ref)));
  if (size > 0 && !bytesEqual(await h(0, size), checkpoint.root)) throw new Error("Die Kacheln passen nicht zum unterschriebenen Stand.");

  let previous = 0;
  if (opts.previousNote) {
    const prevText = await verifySignedNote(opts.previousNote, key, verify);
    if (!prevText) throw new Error("Der gespeicherte vorige Stand ist nicht gültig unterschrieben.");
    const prev = parseCheckpoint(prevText);
    previous = prev.size;
    if (prev.size > size) throw new Error(`Das Register ist geschrumpft: vorher ${prev.size}, jetzt ${size} Einträge.`);
    if (prev.size === size) {
      if (!bytesEqual(prev.root, checkpoint.root)) throw new Error(`Gleiche Größe ${size}, aber andere Wurzel: die Vergangenheit wurde umgeschrieben.`);
    } else if (prev.size > 0) {
      const proof = await consistencyProofFrom(prev.size, size, h);
      if (!(await verifyConsistency(c, { m: prev.size, n: size, rootM: prev.root, rootN: checkpoint.root, proof }))) {
        throw new Error(`Der neue Stand (${size}) setzt den vorigen (${prev.size}) nicht fort: die Vergangenheit wurde umgeschrieben.`);
      }
    }
  }

  const kinds: Record<EntryKind, number> = { issue: 0, transfer: 0, redeem: 0, revoke: 0, reinstate: 0 };
  if (opts.full) {
    const hashes: Uint8Array[] = [];
    await readAllEntries(c, checkpoint, files, (_i, leaf, hash) => { kinds[leaf.kind]++; hashes.push(hash); }, opts.onProgress);
    // Jede Kachel dieses Stands aus den Eintraegen neu bauen und mit der
    // veroeffentlichten vergleichen. Die Wurzel oben liest nur die Kacheln, die
    // sie braucht; eine gefaelschte untere Kachel faellt sonst erst dem auf,
    // dessen Beweisweg darueber laeuft (Manipulationstest, Stufe 5).
    const { tiles } = await buildTiles(c, 0, size, hashes, new Map());
    for (const t of tiles) {
      if (!bytesEqual(await files(tilePath(t.ref)), t.data)) throw new Error(`Die Kachel ${tilePath(t.ref)} passt nicht zu den Einträgen.`);
    }
  }
  return { checkpoint, note, added: size - previous, kinds };
}
