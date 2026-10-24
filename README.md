# Passly Register · Wächter (Sandbox)

Dieses Repo beobachtet das **Passly Register** der Testumgebung. Passly
schreibt jedes Ticket und jeden Zustandswechsel (ausgestellt, weitergegeben,
eingelassen, widerrufen) in ein öffentliches, nur wachsendes Register und
unterschreibt regelmäßig dessen Stand. Dieses Repo sorgt dafür, dass Passly
diese Geschichte nicht heimlich umschreiben kann.

Es ist die **Testumgebung**: die Tickets darin sind Testdaten.

## Was hier jede Stunde passiert

Die GitHub Action [`waechter.yml`](.github/workflows/waechter.yml):

1. lädt den aktuellen Stand (`checkpoint`) aus den öffentlichen Dateien
   ([`basis`](basis)) und prüft die Unterschrift gegen den hier festgehaltenen
   Prüfschlüssel ([`vkey`](vkey)),
2. beweist, dass der neue Stand den zuletzt hier gespeicherten **fortsetzt**
   (Konsistenzbeweis nach RFC 9162): nichts wurde gelöscht, geändert oder
   umsortiert,
3. liest **jeden Eintrag** und rechnet die Wurzel neu,
4. macht dasselbe noch einmal mit einer **unabhängigen Implementierung**
   ([`gegenprobe/`](gegenprobe), `golang.org/x/mod/sumdb/tlog`, die Bibliothek
   der Go-Prüfsummendatenbank),
5. committet den neuen Stand, einmal am Tag mit einem **RFC-3161-Zeitstempel**
   ([`zeitstempel/`](zeitstempel)).

Schlägt eine Prüfung fehl, bleibt der alte Stand hier stehen und der Lauf wird
rot. Die Git-Historie dieses Repos ist damit ein Protokoll aller Stände, das
Passly nicht nachträglich ändern kann. Jeder kann es spiegeln.

## Selbst nachprüfen

Mit Node 24 (keine Installation nötig):

```sh
node pruefen.mjs stand --base "$(cat basis)" --vkey vkey --vorher checkpoint --voll
```

Mit Go:

```sh
cd gegenprobe && go run . -base "$(cat ../basis)" -vkey ../vkey -vorher ../checkpoint
```

Einen Zeitstempel prüfen:

```sh
openssl ts -verify -in zeitstempel/<tag>.tsr -data zeitstempel/<tag>.checkpoint \
  -CAfile zeitstempel/freetsa-cacert.pem -untrusted zeitstempel/freetsa-tsa.crt
```

## Für Kassenprüfer

Veranstalter laden im Passly-Dashboard („Im Register nachzählen“) eine Datei
mit dem Prüfschlüssel ihres Events. Damit zählt man unabhängig von Passly nach,
wie viele Tickets ausgestellt, eingelassen und widerrufen wurden:

```sh
node pruefen.mjs nachzaehlen --datei nachzaehlen-<event>.json
```

## Woher die Dateien stammen

`register.ts` und `pruefen.mjs` sind Kopien aus dem Passly-Quellcode
(`packages/core/src/register.ts`, `scripts/register/pruefen.mjs`); die
Spezifikation steht dort in `docs/register-spec.md`. `gegenprobe/` benutzt
davon nichts.
