// Gegenprobe zum Passly Register (docs/plan-passly-register.md, Abschnitt 10):
// prüft Unterschrift, Kacheln, jeden Eintrag und die Fortsetzung eines
// früheren Stands mit golang.org/x/mod/sumdb/tlog und .../note, also mit der
// Implementierung der Go-Prüfsummendatenbank. Kein Code von Passly; stimmt
// sie mit packages/core/src/register.ts überein, haben zwei unabhängige
// Implementierungen dasselbe nachgerechnet.
//
//	go run . -base <url> -vkey <schluessel|datei> [-vorher <checkpoint-datei>]
//
// Exit 0: alles stimmt. Exit 1: Bruch. Exit 2: Aufruf oder Netz.
package main

import (
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

const height = 8 // C2SP tlog-tiles: immer Höhe 8

var base string

type unerreichbar struct{ error }

func hole(path string) ([]byte, error) {
	r, err := http.Get(base + path)
	if err != nil {
		return nil, unerreichbar{err}
	}
	defer r.Body.Close()
	if r.StatusCode >= 500 {
		return nil, unerreichbar{fmt.Errorf("%s: HTTP %d", path, r.StatusCode)}
	}
	if r.StatusCode != 200 {
		return nil, fmt.Errorf("Datei %s fehlt (HTTP %d)", path, r.StatusCode)
	}
	return io.ReadAll(r.Body)
}

// C2SP schreibt "tile/<L>/<N>[.p/<W>]", Go "tile/8/<L>/<N>[.p/<W>]": gleiche Kacheln, Höhe nicht im Pfad.
func kachelPfad(t tlog.Tile) string {
	return strings.Replace(t.Path(), fmt.Sprintf("tile/%d/", height), "tile/", 1)
}

type kacheln struct{}

func (kacheln) Height() int { return height }
func (kacheln) ReadTiles(ts []tlog.Tile) ([][]byte, error) {
	out := make([][]byte, len(ts))
	for i, t := range ts {
		d, err := hole(kachelPfad(t))
		if err != nil {
			return nil, err
		}
		out[i] = d
	}
	return out, nil
}
func (kacheln) SaveTiles([]tlog.Tile, [][]byte) {}

// Checkpoint nach C2SP tlog-checkpoint: Herkunft, Größe, Wurzel (Base64).
func stand(text string, origin string) (tlog.Tree, error) {
	z := strings.Split(text, "\n")
	if len(z) < 3 || z[0] != origin {
		return tlog.Tree{}, errors.New("Stand gehört zu einem anderen Register")
	}
	n, err := strconv.ParseInt(z[1], 10, 64)
	if err != nil || n < 0 {
		return tlog.Tree{}, fmt.Errorf("Größe %q ungültig", z[1])
	}
	h, err := base64.StdEncoding.DecodeString(z[2])
	if err != nil || len(h) != tlog.HashSize {
		return tlog.Tree{}, errors.New("Wurzel ungültig")
	}
	var root tlog.Hash
	copy(root[:], h)
	return tlog.Tree{N: n, Hash: root}, nil
}

// Eintragsbündel: je Eintrag Länge als u16 big-endian, dann die Bytes.
func buendel(b []byte) ([][]byte, error) {
	var out [][]byte
	for i := 0; i < len(b); {
		if i+2 > len(b) {
			return nil, errors.New("Bündel endet mitten in einer Länge")
		}
		n := int(b[i])<<8 | int(b[i+1])
		if i+2+n > len(b) {
			return nil, errors.New("Bündel endet mitten in einem Eintrag")
		}
		out = append(out, b[i+2:i+2+n])
		i += 2 + n
	}
	return out, nil
}

func pruefen(vkey, vorher string) (string, error) {
	verifier, err := note.NewVerifier(vkey)
	if err != nil {
		return "", fmt.Errorf("Prüfschlüssel: %w", err)
	}
	origin := verifier.Name()
	oeffne := func(b []byte) (tlog.Tree, error) {
		n, err := note.Open(b, note.VerifierList(verifier))
		if err != nil {
			return tlog.Tree{}, fmt.Errorf("Unterschrift: %w", err)
		}
		return stand(n.Text, origin)
	}

	cp, err := hole("checkpoint")
	if err != nil {
		return "", err
	}
	tree, err := oeffne(cp)
	if err != nil {
		return "", err
	}

	// TileHashReader prüft jede gelesene Kachel gegen die Wurzel des Stands.
	hr := tlog.TileHashReader(tree, kacheln{})
	root, err := tlog.TreeHash(tree.N, hr)
	if err != nil {
		return "", fmt.Errorf("Kacheln: %w", err)
	}
	if root != tree.Hash {
		return "", errors.New("Kacheln passen nicht zur Wurzel")
	}

	// Jeder Eintrag: sein Hash muss der Blatt-Hash in der (geprüften) Kachel sein.
	for start := int64(0); start < tree.N; start += 256 {
		w := min(256, tree.N-start)
		pfad := kachelPfad(tlog.Tile{H: height, L: 0, N: start / 256, W: int(w)})
		data, err := hole(strings.Replace(pfad, "tile/0/", "tile/entries/", 1))
		if err != nil {
			return "", err
		}
		eintraege, err := buendel(data)
		if err != nil {
			return "", err
		}
		if int64(len(eintraege)) != w {
			return "", fmt.Errorf("Bündel ab %d hat %d statt %d Einträge", start, len(eintraege), w)
		}
		idx := make([]int64, w)
		for j := range idx {
			idx[j] = tlog.StoredHashIndex(0, start+int64(j))
		}
		hashes, err := hr.ReadHashes(idx)
		if err != nil {
			return "", err
		}
		for j, e := range eintraege {
			if tlog.RecordHash(e) != hashes[j] {
				return "", fmt.Errorf("Eintrag %d passt nicht zu seiner Kachel", start+int64(j))
			}
		}
	}

	bericht := fmt.Sprintf("stimmt: %d Einträge, Wurzel %s", tree.N, base64.StdEncoding.EncodeToString(tree.Hash[:]))
	if vorher != "" {
		alt, err := os.ReadFile(vorher)
		if err != nil {
			return "", err
		}
		old, err := oeffne(alt)
		if err != nil {
			return "", fmt.Errorf("voriger Stand: %w", err)
		}
		if old.N > tree.N {
			return "", fmt.Errorf("Register geschrumpft: vorher %d, jetzt %d", old.N, tree.N)
		}
		proof, err := tlog.ProveTree(tree.N, old.N, hr)
		if err != nil {
			return "", err
		}
		if err := tlog.CheckTree(proof, tree.N, tree.Hash, old.N, old.Hash); err != nil {
			return "", fmt.Errorf("setzt den vorigen Stand (%d) nicht fort: %w", old.N, err)
		}
		bericht += fmt.Sprintf(", setzt Stand %d fort", old.N)
	}
	return bericht, nil
}

func main() {
	b := flag.String("base", "", "Adresse der öffentlichen Dateien")
	k := flag.String("vkey", "", "Prüfschlüssel des Registers (oder Datei)")
	v := flag.String("vorher", "", "früherer Checkpoint (Datei)")
	flag.Parse()
	if *b == "" || *k == "" {
		flag.Usage()
		os.Exit(2)
	}
	base = strings.TrimSuffix(*b, "/") + "/"
	vkey := *k
	if d, err := os.ReadFile(vkey); err == nil {
		vkey = strings.TrimSpace(string(d))
	}
	bericht, err := pruefen(vkey, *v)
	if err != nil {
		var u unerreichbar
		if errors.As(err, &u) {
			fmt.Fprintln(os.Stderr, "FEHLER:", err)
			os.Exit(2)
		}
		fmt.Fprintln(os.Stderr, "BRUCH:", err)
		os.Exit(1)
	}
	fmt.Println(bericht)
}
