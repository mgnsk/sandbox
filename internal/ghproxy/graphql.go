package ghproxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"
)

type operation struct {
	kind, name string
	fields     []string
}

// graphQLOperations lists each operation in a GraphQL request body, with
// its top-level fields, plus the request's variables - or ok=false if it
// isn't a single, parseable GraphQL request.
func graphQLOperations(body []byte) (ops []operation, variables json.RawMessage, ok bool) {
	body = bytes.TrimPrefix(body, []byte("\xef\xbb\xbf"))
	if !utf8.Valid(body) {
		return nil, nil, false
	}
	var request map[string]json.RawMessage
	if json.Unmarshal(body, &request) != nil {
		return nil, nil, false
	}
	var query string
	if raw, found := request["query"]; !found || json.Unmarshal(raw, &query) != nil {
		return nil, nil, false
	}
	doc, err := parser.ParseQuery(&ast.Source{Input: query})
	if err != nil {
		return nil, nil, false
	}
	for _, op := range doc.Operations {
		fields := []string{}
		for _, sel := range op.SelectionSet {
			if f, isField := sel.(*ast.Field); isField {
				fields = append(fields, f.Name)
			}
		}
		ops = append(ops, operation{string(op.Operation), op.Name, fields})
	}
	if len(ops) == 0 {
		return nil, nil, false
	}
	return ops, request["variables"], true
}

// describeWrite describes a write for the approval popup, or says the
// request only reads. body is the body of a request to the GraphQL
// endpoint, nil for everything else.
func describeWrite(method, host, path string, body []byte) (string, bool) {
	target := method + " " + host + path
	if body == nil {
		if method == "GET" || method == "HEAD" {
			return "", false
		}
		return target, true
	}

	ops, variables, ok := graphQLOperations(body)
	if !ok {
		return target + "\n\n(not a GraphQL request this proxy understands)", true
	}
	// Any non-query operation counts, whichever one operationName selects.
	if method == "POST" {
		reads := true
		for _, op := range ops {
			if op.kind != "query" {
				reads = false
			}
		}
		if reads {
			return "", false
		}
	}
	lines := []string{target, ""}
	for _, op := range ops {
		name := op.name
		if name == "" {
			name = "(anonymous)"
		}
		fields := strings.Join(op.fields, ", ")
		if fields == "" {
			fields = "-"
		}
		lines = append(lines, fmt.Sprintf("%s %s: %s", op.kind, name, fields))
	}
	if v, err := parseJSON(variables); err == nil && v.truthy() {
		var b strings.Builder
		v.write(&b, "")
		lines = append(lines, "", "variables:", b.String())
	}
	return strings.Join(lines, "\n"), true
}

// jsonValue is a JSON value with its objects' keys in order, for showing
// variables as the client sent them.
type jsonValue struct {
	scalar string // A literal, for anything but an object or array.
	object bool
	array  bool
	keys   []string
	values []jsonValue
}

func parseJSON(raw json.RawMessage) (jsonValue, error) {
	if len(raw) == 0 {
		return jsonValue{scalar: "null"}, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	return decodeValue(dec)
}

func decodeValue(dec *json.Decoder) (jsonValue, error) {
	tok, err := dec.Token()
	if err != nil {
		return jsonValue{}, err
	}
	switch t := tok.(type) {
	case json.Delim:
		v := jsonValue{object: t == '{', array: t == '['}
		for dec.More() {
			if v.object {
				key, err := dec.Token()
				if err != nil {
					return jsonValue{}, err
				}
				v.keys = append(v.keys, key.(string))
			}
			item, err := decodeValue(dec)
			if err != nil {
				return jsonValue{}, err
			}
			v.values = append(v.values, item)
		}
		if _, err := dec.Token(); err != nil && err != io.EOF {
			return jsonValue{}, err
		}
		return v, nil
	case string:
		return jsonValue{scalar: quote(t)}, nil
	case json.Number:
		return jsonValue{scalar: t.String()}, nil
	case bool:
		return jsonValue{scalar: strconv.FormatBool(t)}, nil
	default:
		return jsonValue{scalar: "null"}, nil
	}
}

// truthy is Python's bool() of the value.
func (v jsonValue) truthy() bool {
	switch {
	case v.object || v.array:
		return len(v.values) > 0
	case v.scalar == "null", v.scalar == "false", v.scalar == `""`:
		return false
	}
	if f, err := strconv.ParseFloat(v.scalar, 64); err == nil {
		return f != 0
	}
	return true
}

// write writes v as Python's json.dumps(v, indent=2, ensure_ascii=False).
func (v jsonValue) write(b *strings.Builder, indent string) {
	open, close := "[", "]"
	if v.object {
		open, close = "{", "}"
	}
	switch {
	case !v.object && !v.array:
		b.WriteString(v.scalar)
		return
	case len(v.values) == 0:
		b.WriteString(open + close)
		return
	}
	inner := indent + "  "
	b.WriteString(open)
	for i, item := range v.values {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString("\n" + inner)
		if v.object {
			b.WriteString(quote(v.keys[i]) + ": ")
		}
		item.write(b, inner)
	}
	b.WriteString("\n" + indent + close)
}

// quote is a JSON string as Python writes it without ensure_ascii.
func quote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			if r < 0x20 {
				fmt.Fprintf(&b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}
