// Command sentari-evidence-verify — offline verifier CLI (spec v0.1).
//
// Usage:
//
//	sentari-evidence-verify PACK [--pubkey B64] [--expected-key-id ID] [--json]
//
// PACK is a .json (flat server download or {payload,signature,frozen_inputs}
// wrapper), a .zip, or a directory containing manifest.json + evidence.json +
// signature.json (+ frozen_inputs.json).
//
// Exit codes: 0 = verified, 2 = tampered, 3 = key_unknown, 4 = usage/parse error.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

const usage = "usage: sentari-evidence-verify PACK [--pubkey B64] [--expected-key-id ID] [--json]"

var errHelp = errors.New("help requested")

type cliArgs struct {
	pack        string
	pubkey      *string
	expectedKID *string
	jsonOutput  bool
}

func parseArgs(args []string) (cliArgs, error) {
	var c cliArgs
	packSet := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--json":
			c.jsonOutput = true
		case a == "-h" || a == "--help":
			return c, errHelp
		case a == "--pubkey":
			i++
			if i >= len(args) {
				return c, errors.New("--pubkey requires a value")
			}
			v := args[i]
			c.pubkey = &v
		case strings.HasPrefix(a, "--pubkey="):
			v := strings.TrimPrefix(a, "--pubkey=")
			c.pubkey = &v
		case a == "--expected-key-id":
			i++
			if i >= len(args) {
				return c, errors.New("--expected-key-id requires a value")
			}
			v := args[i]
			c.expectedKID = &v
		case strings.HasPrefix(a, "--expected-key-id="):
			v := strings.TrimPrefix(a, "--expected-key-id=")
			c.expectedKID = &v
		case strings.HasPrefix(a, "-"):
			return c, fmt.Errorf("unknown flag: %s", a)
		default:
			if packSet {
				return c, errors.New("multiple pack arguments given")
			}
			c.pack = a
			packSet = true
		}
	}
	if !packSet {
		return c, errors.New("missing pack argument")
	}
	return c, nil
}

func exitCode(verdict string) int {
	switch verdict {
	case "verified":
		return 0
	case "tampered":
		return 2
	default: // key_unknown (and any unexpected token)
		return 3
	}
}

// jsonReport mirrors the Python --json field order.
type jsonReport struct {
	Verdict              string          `json:"verdict"`
	PayloadIntact        *bool           `json:"payload_intact"`
	FrozenInputsValid    *bool           `json:"frozen_inputs_valid"`
	SignatureValid       *bool           `json:"signature_valid"`
	SigFieldsConsistent  *bool           `json:"sig_fields_consistent"`
	ManifestValid        *bool           `json:"manifest_valid"`
	KeyIDMatchesMaterial *bool           `json:"key_id_matches_material"`
	KeyIDMatchesAnchor   *bool           `json:"key_id_matches_anchor"`
	PerSource            map[string]bool `json:"per_source"`
	Notes                []string        `json:"notes"`
}

func run(args []string, stdout, stderr *os.File) int {
	c, err := parseArgs(args)
	if err != nil {
		if errors.Is(err, errHelp) {
			fmt.Fprintln(stdout, usage)
			return 0
		}
		fmt.Fprintf(stderr, "%s\n%s\n", err, usage)
		return 4
	}

	payload, signature, frozen, manifestCtx, lerr := loadArtifact(c.pack)
	if lerr != nil {
		fmt.Fprintf(stderr, "could not read pack: %s\n", lerr)
		return 4
	}

	r := verifyPack(payload, signature, frozen, manifestCtx, c.pubkey, c.expectedKID)
	verdict := r.verdict()

	if c.jsonOutput {
		rep := jsonReport{
			Verdict:              verdict,
			PayloadIntact:        r.PayloadIntact,
			FrozenInputsValid:    r.FrozenInputsValid,
			SignatureValid:       r.SignatureValid,
			SigFieldsConsistent:  r.SigFieldsConsistent,
			ManifestValid:        r.ManifestValid,
			KeyIDMatchesMaterial: r.KeyIDMatchesMaterial,
			KeyIDMatchesAnchor:   r.KeyIDMatchesAnchor,
			PerSource:            r.PerSource,
			Notes:                r.Notes,
		}
		enc := json.NewEncoder(stdout)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
	} else {
		fmt.Fprintf(stdout, "verdict: %s\n", strings.ToUpper(verdict))
		fmt.Fprintf(stdout, "  payload_intact       : %s\n", triStr(r.PayloadIntact))
		fmt.Fprintf(stdout, "  frozen_inputs_valid  : %s\n", triStr(r.FrozenInputsValid))
		fmt.Fprintf(stdout, "  signature_valid      : %s\n", triStr(r.SignatureValid))
		fmt.Fprintf(stdout, "  sig_fields_consistent: %s\n", triStr(r.SigFieldsConsistent))
		fmt.Fprintf(stdout, "  manifest_valid       : %s\n", triStr(r.ManifestValid))
		fmt.Fprintf(stdout, "  key_id (material)    : %s\n", triStr(r.KeyIDMatchesMaterial))
		fmt.Fprintf(stdout, "  key_id (anchor)      : %s\n", triStr(r.KeyIDMatchesAnchor))
		for _, n := range r.Notes {
			fmt.Fprintf(stdout, "  · %s\n", n)
		}
	}
	return exitCode(verdict)
}

// triStr renders a *bool as Python would render bool | None: True / False / None.
func triStr(p *bool) string {
	if p == nil {
		return "None"
	}
	if *p {
		return "True"
	}
	return "False"
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}
