package main

import (
	"context"
	"log"

	"github.com/jonascheng/opa-demo/policy"

	"github.com/open-policy-agent/opa/rego"
)

var (
	policyPath   = "policy/rbac.authz.rego"
	defaultQuery = "x = data.rbac.authz.eval_result"
)

type evalResult struct {
	Allow      bool     `json:"allow"`
	DenyReason []string `json:"denyReason"`
}

type input struct {
	Role          []string `json:"role"`
	Action        string   `json:"action"`
	Object        string   `json:"object"`
	Group         string   `json:"group"`
	AuthzedGroups []string `json:"authzedGroups"`
}

func main() {
	s := input{
		Role:          []string{"viewer"},
		Action:        "view",
		Object:        "agent-groups",
		Group:         "group1",
		AuthzedGroups: []string{"group1", "group2", "group3"},
	}

	input := map[string]interface{}{
		"role":          s.Role,
		"action":        s.Action,
		"object":        s.Object,
		"group":         s.Group,
		"authzedGroups": s.AuthzedGroups,
	}

	p, err := policy.ReadPolicy(policyPath)
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.TODO()
	query, err := rego.New(
		rego.Query(defaultQuery),
		rego.Module(policyPath, string(p)),
	).PrepareForEval(ctx)
	if err != nil {
		log.Fatalf("initial rego error: %v", err)
	}

	ok, _ := eval(ctx, query, input)
	log.Println(ok)
}

func eval(ctx context.Context, query rego.PreparedEvalQuery, input map[string]interface{}) (evalResult, error) {
	var result evalResult
	rs, err := query.Eval(ctx, rego.EvalInput(input))

	// log.Printf("%v\n", rs[0].Bindings["x"])

	if err != nil {
		log.Fatalf("evaluation error: %v", err)
	} else if len(rs) == 0 {
		log.Fatal("undefined result", err)
	} else {
		var allow, ok bool
		denyReason := []string{}
		if allow, ok = rs[0].Bindings["x"].(map[string]interface{})["allow"].(bool); !ok {
			log.Fatalf("unexpected result type: %v", rs[0].Bindings["x"].(map[string]interface{})["allow"])
		}
		if !allow {
			// t := reflect.TypeOf(rs[0].Bindings["x"].(map[string]interface{})["denyReason"].([]interface{})[0])
			// log.Print(t)
			reasons := rs[0].Bindings["x"].(map[string]interface{})["denyReason"].([]interface{})
			for _, r := range reasons {
				var reason string
				if reason, ok = r.(string); !ok {
					log.Fatalf("unexpected result type: %v", r)
				}
				denyReason = append(denyReason, reason)
			}
		}
		result = evalResult{allow, denyReason}
	}

	return result, nil
}
