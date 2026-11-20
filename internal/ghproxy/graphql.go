package ghproxy

import (
	"bytes"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"path"
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

// request is a GraphQL request body: its operations, its document as the
// client sent it, and its variables.
type request struct {
	ops       []operation
	query     string
	variables jsontext.Value
}

// parseGraphQL reads a GraphQL request body, or returns an error if it
// isn't a single request this proxy understands.
func parseGraphQL(body []byte) (*request, error) {
	var req struct {
		Query     string         `json:"query"`
		Variables jsontext.Value `json:"variables"`
	}
	if err := json.Unmarshal(bytes.TrimPrefix(body, []byte("\uFEFF")), &req); err != nil {
		return nil, err
	}
	doc, err := parser.ParseQuery(&ast.Source{Input: req.Query})
	if err != nil {
		return nil, err
	}
	if len(doc.Operations) == 0 {
		return nil, errors.New("no operation")
	}
	ops := make([]operation, 0, len(doc.Operations))
	for _, op := range doc.Operations {
		ops = append(ops, operation{op.Operation, op.Name, topFields(op.SelectionSet, doc.Fragments, 0)})
	}
	return &request{ops, req.Query, req.Variables}, nil
}

// topFields are the names of an operation's top-level fields: what it
// reads or does. Through fragments too, which would otherwise hide them.
func topFields(set ast.SelectionSet, fragments ast.FragmentDefinitionList, depth int) []string {
	var fields []string
	for _, sel := range set {
		switch s := sel.(type) {
		case *ast.Field:
			fields = append(fields, s.Name)
		case *ast.InlineFragment:
			fields = append(fields, topFields(s.SelectionSet, fragments, depth)...)
		case *ast.FragmentSpread:
			// A fragment can't contain itself, but nothing has checked.
			if def := fragments.ForName(s.Name); def != nil && depth < 8 {
				fields = append(fields, topFields(def.SelectionSet, fragments, depth+1)...)
			}
		}
	}
	return fields
}

// describe describes a write for the approval popup, or returns "" for a
// read: REST GET/HEAD, and GraphQL documents of queries only, whichever one
// operationName selects.
//
// A GraphQL request is a read only as the one thing this proxy knows the
// endpoint to take: a POST of a JSON body, with nothing in the URL's query
// that a server might read a document from instead. A write shows the
// operations, then the document and variables as sent: what a mutation
// does is in its arguments.
func describe(r *http.Request, host string) (string, error) {
	target := apiproxy.Target(r, host)
	if host != apiHost || strings.ToLower(path.Clean("/"+r.URL.Path)) != "/graphql" {
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			return "", nil
		}
		return apiproxy.DescribeWrite(r, host)
	}
	body, err := apiproxy.ReadBody(r, maxGraphQLBody)
	if err != nil {
		return "", err
	}
	req, err := parseGraphQL(body)
	if err != nil {
		return target + "\n\n(not a GraphQL request this proxy understands)", nil
	}
	writes := func(op operation) bool { return op.kind != ast.Query }
	if r.Method == http.MethodPost && r.URL.RawQuery == "" && jsonBody(r) && !slices.ContainsFunc(req.ops, writes) {
		return "", nil
	}
	lines := []string{target, ""}
	for _, op := range req.ops {
		lines = append(lines, op.String())
	}
	lines = append(lines, "", apiproxy.Shown(req.query))
	if shown := showVariables(req.variables); shown != "" {
		lines = append(lines, "", "variables:", apiproxy.Shown(shown))
	}
	return strings.Join(lines, "\n"), nil
}

// jsonBody says whether r says its body is JSON, or nothing.
func jsonBody(r *http.Request) bool {
	kind, _, _ := strings.Cut(r.Header.Get("Content-Type"), ";")
	kind = strings.ToLower(strings.TrimSpace(kind))
	return kind == "" || kind == "application/json"
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
