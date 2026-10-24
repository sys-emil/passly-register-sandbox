#!/usr/bin/env node
/**
 * Prüfwerkzeug des Passly Registers (docs/plan-passly-register.md, Stufe 5).
 * Rechnet alles selbst aus den öffentlichen Dateien nach, mit derselben
 * Implementierung wie Browser und Sequencer (packages/core/src/register.ts,
 * von Node 24 direkt als TypeScript geladen; im Wächter-Repo liegt sie als
 * register.ts daneben).
 *
 *   node pruefen.mjs stand --base <url> --vkey <schluessel|datei> [--vorher <checkpoint-datei>] [--voll] [--schreibe <datei>]
 *       Unterschrift des neuesten Stands; mit --vorher, dass er den gespeicherten
 *       fortsetzt (Konsistenzbeweis); mit --voll zusätzlich jeden Eintrag.
 *       --schreibe legt den geprüften Stand ab (für den nächsten Lauf).
 *
 *   node pruefen.mjs nachzaehlen --datei <nachzaehlen-….json>
 *       Die Datei für den Kassenprüfer aus dem Dashboard: zählt das Event zum
 *       darin unterschriebenen Stand nach und prüft, dass der heutige Stand ihn
 *       fortsetzt.
 *
 * Exit-Codes: 0 alles stimmt · 1 Bruch (Manipulation oder Fehler im Register)
 *             · 2 Aufruf falsch oder Register nicht erreichbar.
 */
import { createHash, createHmac, createPublicKey, verify as edVerify } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const hier = path.dirname(fileURLToPath(import.meta.url));
const kern = [path.join(hier, 'register.ts'), path.join(hier, '../../packages/core/src/register.ts')].find((p) => fs.existsSync(p));
if (!kern) { console.error('register.ts nicht gefunden'); process.exit(2); }
// register.ts liegt ohne "type": "module" daneben; Node erkennt es selbst und
// warnt nur darüber. Die Warnung ist hier Rauschen, andere bleiben sichtbar.
const warnen = process.emitWarning;
process.emitWarning = (w, ...rest) => {
  const code = typeof rest[0] === 'object' ? rest[0]?.code : rest[1];
  if (code === 'MODULE_TYPELESS_PACKAGE_JSON') return;
  return warnen.call(process, w, ...rest);
};
const R = await import(pathToFileURL(kern).href);

const c = {
  sha256: async (d) => new Uint8Array(createHash('sha256').update(d).digest()),
  hmacSha256: async (k, d) => new Uint8Array(createHmac('sha256', k).update(d).digest()),
};
const SPKI_ED25519 = Buffer.from('302a300506032b6570032100', 'hex');
const ed = async (pub, sig, msg) =>
  edVerify(null, msg, createPublicKey({ key: Buffer.concat([SPKI_ED25519, pub]), format: 'der', type: 'spki' }), sig);

const args = { _: [] };
for (let i = 2; i < process.argv.length; i++) {
  const a = process.argv[i];
  if (a.startsWith('--')) {
    const [k, v] = a.slice(2).split('=', 2);
    args[k] = v ?? (process.argv[i + 1] && !process.argv[i + 1].startsWith('--') ? process.argv[++i] : true);
  } else args._.push(a);
}

class Unerreichbar extends Error {}
/** Öffentliche Dateien per HTTP; der Checkpoint ohne Cache, alles andere ist unveränderlich. */
function dateien(base, checkpointText) {
  const b = base.endsWith('/') ? base : base + '/';
  return async (p) => {
    if (p === 'checkpoint' && checkpointText !== undefined) return new TextEncoder().encode(checkpointText);
    let r;
    try { r = await fetch(b + p, p === 'checkpoint' ? { cache: 'no-store' } : {}); } catch (e) { throw new Unerreichbar(`${p}: ${e.message}`); }
    if (r.status >= 500) throw new Unerreichbar(`${p}: HTTP ${r.status}`);
    if (!r.ok) throw new Error(`Datei ${p} fehlt (HTTP ${r.status}).`);
    return new Uint8Array(await r.arrayBuffer());
  };
}

const lies = (v) => (v && fs.existsSync(v) ? fs.readFileSync(v, 'utf8').trim() : v);
const zahl = (n) => n.toLocaleString('de-DE');
const ausgabe = (o) => console.log(args.json ? JSON.stringify(o) : Object.entries(o).filter(([, v]) => v !== undefined).map(([k, v]) => `${k}: ${typeof v === 'object' ? JSON.stringify(v) : v}`).join('\n'));

async function stand() {
  if (!args.base || !args.vkey) throw Object.assign(new Error('stand braucht --base und --vkey'), { code: 2 });
  const key = await R.parseVerifierKey(c, lies(args.vkey));
  const vorher = args.vorher && fs.existsSync(args.vorher) ? fs.readFileSync(args.vorher, 'utf8') : undefined;
  const t0 = Date.now();
  const r = await R.watchRegister(c, ed, key, dateien(args.base), { previousNote: vorher, full: !!args.voll });
  if (args.schreibe) fs.writeFileSync(args.schreibe, r.note);
  ausgabe({
    ergebnis: 'stimmt',
    eintraege: r.checkpoint.size,
    wurzel: R.toBase64(r.checkpoint.root),
    neu: vorher ? r.added : undefined,
    ...(args.voll ? { arten: r.kinds } : {}),
    dauer_ms: Date.now() - t0,
  });
}

async function nachzaehlen() {
  if (!args.datei) throw Object.assign(new Error('nachzaehlen braucht --datei'), { code: 2 });
  const d = JSON.parse(fs.readFileSync(args.datei, 'utf8'));
  if (!d.pruefschluesselEvent || !d.pruefschluesselRegister || !d.stand?.unterschrieben) throw new Error('Das ist keine Nachzähl-Datei von Passly.');
  const key = await R.parseVerifierKey(c, d.pruefschluesselRegister);
  const base = args.base || d.dateien;
  // Zählen zum Stand in der Datei (dessen Kacheln sind unveränderlich und liegen noch da) …
  const r = await R.countScope(c, ed, key, dateien(base, d.stand.unterschrieben), R.fromHex(d.pruefschluesselEvent));
  // … und prüfen, dass der heutige Stand diesen fortsetzt, also nichts davon später verschwand.
  const heute = await R.watchRegister(c, ed, key, dateien(base), { previousNote: d.stand.unterschrieben });
  const t = r.tally;
  const gezaehlt = { ausgestellt: t.issued, weitergegeben: t.transferred, eingelassen: t.redeemed, widerrufen: t.revoked, wiederGueltig: t.reinstated };
  const abweichung = Object.entries(gezaehlt).filter(([k, v]) => d.gezaehlt?.[k] !== undefined && d.gezaehlt[k] !== v);
  ausgabe({
    ergebnis: abweichung.length ? 'weicht ab' : 'stimmt',
    event: `${d.event?.name ?? '?'} (${d.event?.date ?? '?'})`,
    stand: `${zahl(r.checkpoint.size)} Einträge, heute ${zahl(heute.checkpoint.size)} und fortgesetzt`,
    gezaehlt,
    gueltig: t.issued - t.revoked + t.reinstated,
    ...(abweichung.length ? { abweichend_zur_datei: Object.fromEntries(abweichung.map(([k, v]) => [k, `Datei ${d.gezaehlt[k]}, nachgezählt ${v}`])) } : {}),
  });
  if (abweichung.length) process.exitCode = 1;
}

const befehle = { stand, nachzaehlen };
const befehl = befehle[args._[0]];
if (!befehl) {
  console.error('Aufruf: pruefen.mjs stand --base <url> --vkey <schluessel|datei> [--vorher <datei>] [--voll] [--schreibe <datei>]\n        pruefen.mjs nachzaehlen --datei <nachzaehlen-….json>');
  process.exit(2);
}
try {
  await befehl();
} catch (e) {
  const code = e instanceof Unerreichbar || e.code === 2 ? 2 : 1;
  console.error(`${code === 1 ? 'BRUCH' : 'FEHLER'}: ${e.message}`);
  process.exit(code);
}
