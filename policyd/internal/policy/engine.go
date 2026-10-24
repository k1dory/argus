// Package policy evaluates Policy-as-Code rules (OPA/Rego) against
// Wazuh entities. Each policy package must export a `result` object:
//
//	result := {"compliant": <bool>, "violations": [<string>, ...]}
package policy

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/open-policy-agent/opa/v1/rego"
)

type Verdict struct {
	Compliant  bool
	Violations []string
}

type Engine struct {
	queries map[string]rego.PreparedEvalQuery
}

// New loads every .rego/.json file from dir (tests excluded) and prepares
// one query per package name, e.g. "agent" -> data.wazuh.agent.result.
func New(ctx context.Context, dir string, packages []string) (*Engine, error) {
	skipTests := func(abspath string, info os.FileInfo, depth int) bool {
		return strings.HasSuffix(abspath, "_test.rego")
	}
	e := &Engine{queries: make(map[string]rego.PreparedEvalQuery, len(packages))}
	for _, pkg := range packages {
		q, err := rego.New(
			rego.Query("data.wazuh."+pkg+".result"),
			rego.Load([]string{dir}, skipTests),
		).PrepareForEval(ctx)
		if err != nil {
			return nil, fmt.Errorf("prepare policy %q: %w", pkg, err)
		}
		e.queries[pkg] = q
	}
	return e, nil
}

func (e *Engine) Eval(ctx context.Context, pkg string, input any) (Verdict, error) {
	q, ok := e.queries[pkg]
	if !ok {
		return Verdict{}, fmt.Errorf("unknown policy package %q", pkg)
	}
	if input == nil {
		// Без input политика не видит ни одного поля и все правила undefined;
		// пустой объект даёт честные нарушения «поле отсутствует».
		input = map[string]any{}
	}
	rs, err := q.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return Verdict{}, fmt.Errorf("eval policy %q: %w", pkg, err)
	}
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return Verdict{}, fmt.Errorf("policy %q produced no result", pkg)
	}
	obj, ok := rs[0].Expressions[0].Value.(map[string]any)
	if !ok {
		return Verdict{}, fmt.Errorf("policy %q: result is not an object", pkg)
	}
	v := Verdict{}
	v.Compliant, _ = obj["compliant"].(bool)
	if raw, ok := obj["violations"].([]any); ok {
		for _, item := range raw {
			if s, ok := item.(string); ok {
				v.Violations = append(v.Violations, s)
			}
		}
	}
	return v, nil
}
