// Canonical JSON (spec §4).
//
// canonicalJSON reproduces, byte-for-byte, the normative Python definition:
//
//	json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
//
// Go's encoding/json does NOT match this out of the box (it HTML-escapes
// `<`, `>`, `&`, escapes U+2028/U+2029, and reorders nothing), so we serialise
// by hand:
//
//   - object keys sorted lexicographically by Unicode code point (== byte order
//     for UTF-8, which sort.Strings gives us);
//   - `{"k":v,...}` and `[v,...]` with NO insignificant whitespace;
//   - strings: escape only `"`→\", `\`→\\, and the C0 control range using
//     Python's short forms (\b \t \n \f \r) else \u00XX (lowercase hex); every
//     other rune — including `<` `>` `&` `/`, U+2028/U+2029, and all non-ASCII —
//     is emitted as RAW UTF-8 (ensure_ascii=False);
//   - numbers emitted verbatim from json.Number so integers keep their exact
//     source form (the input JSON is parsed with Decoder.UseNumber());
//   - booleans true/false, null.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
)

// canonicalJSON returns the canonical (spec §4) UTF-8 byte encoding of v.
func canonicalJSON(v interface{}) []byte {
	var buf bytes.Buffer
	encodeValue(&buf, v)
	return buf.Bytes()
}

func encodeValue(buf *bytes.Buffer, v interface{}) {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		encodeString(buf, t)
	case json.Number:
		// Verbatim source text — integers keep their exact form (spec §4:
		// payloads never emit floats in hashed fields).
		buf.WriteString(t.String())
	case int:
		buf.WriteString(strconv.Itoa(t))
	case int64:
		buf.WriteString(strconv.FormatInt(t, 10))
	case float64:
		// Not used by conformant payloads (spec forbids floats in hashed
		// fields); present only so a stray value never panics the encoder.
		buf.WriteString(strconv.FormatFloat(t, 'g', -1, 64))
	case map[string]interface{}:
		encodeObject(buf, t)
	case []interface{}:
		buf.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			encodeValue(buf, e)
		}
		buf.WriteByte(']')
	default:
		// Unknown Go type: stringify deterministically rather than panic.
		encodeString(buf, fmt.Sprintf("%v", t))
	}
}

func encodeObject(buf *bytes.Buffer, m map[string]interface{}) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// Byte-wise sort of UTF-8 == Unicode code-point sort == Python sort_keys.
	sort.Strings(keys)
	buf.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		encodeString(buf, k)
		buf.WriteByte(':')
		encodeValue(buf, m[k])
	}
	buf.WriteByte('}')
}

// encodeString mirrors Python's json string escaping with ensure_ascii=False.
func encodeString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				// Remaining C0 controls → \u00XX, lowercase hex (Python form).
				fmt.Fprintf(buf, `\u%04x`, r)
			} else {
				// Raw UTF-8: non-ASCII unescaped, `<` `>` `&` `/` and
				// U+2028/U+2029 NOT escaped.
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}
