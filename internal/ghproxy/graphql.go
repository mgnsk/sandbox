package ghproxy

import (
	"bytes"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"

	"github.com/mgnsk/sandbox/internal/apiproxy"
)

// GraphQL bodies are read in full to classify them; everything else
// streams.
const maxGraphQLBody = 10 << 20

// operation is one operation of a GraphQL document, with its top-level
// fields.
type operation struct {
	kind   ast.Operation
	name   string
	fields []string
}

func (op operation) String() string {
	name := op.name
	if name == "" {
		name = "(anonymous)"
	}
	fields := strings.Join(op.fields, ", ")
	if fields == "" {
		fields = "-"
	}
	return fmt.Sprintf("%s %s: %s", op.kind, name, fields)
}

// parseGraphQL reads a GraphQL request body: its operations and variables,
// or an error if it isn't a single request this proxy understands.
func parseGraphQL(body []byte) ([]operation, jsontext.Value, error) {
	var req struct {
		Query     string         `json:"query"`
		Variables jsontext.Value `json:"variables"`
	}
	if err := json.Unmarshal(bytes.TrimPrefix(body, []byte("\uFEFF")), &req); err != nil {
		return nil, nil, err
	}
	doc, err := parser.ParseQuery(&ast.Source{Input: req.Query})
	if err != nil {
		return nil, nil, err
	}
	if len(doc.Operations) == 0 {
		return nil, nil, errors.New("no operation")
	}
	ops := make([]operation, 0, len(doc.Operations))
	for _, op := range doc.Operations {
		var fields []string
		for _, sel := range op.SelectionSet {
			if f, ok := sel.(*ast.Field); ok {
				fields = append(fields, f.Name)
			}
		}
		ops = append(ops, operation{op.Operation, op.Name, fields})
	}
	return ops, req.Variables, nil
}

// describe describes a write for the approval popup, or returns "" for a
// read: REST GET/HEAD, and GraphQL documents of queries only, whichever one
// operationName selects.
func describe(r *http.Request, host string) (string, error) {
	target := apiproxy.Target(r, host)
	if host != apiHost || strings.TrimRight(r.URL.Path, "/") != "/graphql" {
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			return "", nil
		}
		return target, nil
	}
	body, err := apiproxy.ReadBody(r, maxGraphQLBody)
	if err != nil {
		return "", err
	}
	ops, variables, err := parseGraphQL(body)
	if err != nil {
		return target + "\n\n(not a GraphQL request this proxy understands)", nil
	}
	writes := func(op operation) bool { return op.kind != ast.Query }
	if r.Method == http.MethodPost && !slices.ContainsFunc(ops, writes) {
		return "", nil
	}
	lines := []string{target, ""}
	for _, op := range ops {
		lines = append(lines, op.String())
	}
	if shown := showVariables(variables); shown != "" {
		lines = append(lines, "", "variables:", shown)
	}
	return strings.Join(lines, "\n"), nil
}

// showVariables is the variables as the client sent them, indented; "" for
// none.
func showVariables(v jsontext.Value) string {
	compact := v.Clone()
	if compact.Compact() != nil {
		return ""
	}
	switch string(compact) {
	case "", "null", "{}", "[]", `""`, "false", "0":
		return ""
	}
	indented := v.Clone()
	if indented.Indent(jsontext.WithIndent("  ")) != nil {
		return ""
	}
	return string(indented)
}
