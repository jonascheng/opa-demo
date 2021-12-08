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
	Allow      bool   `json:"allow"`
	DenyReason string `json:"denyReason"`
}

type input struct {
	Role          []string `json:"role"`
	Action        string   `json:"action"`
	Object        string   `json:"object"`
	Group         string   `json:"group"`
	GrantedGroups []string `json:"grantedGroups"`
}

func main() {
	s := input{
		Role:          []string{"viewer"},
		Action:        "view",
		Object:        "agent-groups",
		Group:         "group1",
		GrantedGroups: []string{"group1", "group2", "group3"},
	}

	input := map[string]interface{}{
		"role":          s.Role,
		"action":        s.Action,
		"object":        s.Object,
		"group":         s.Group,
		"grantedGroups": s.GrantedGroups,
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

	if err != nil {
		log.Fatalf("evaluation error: %v", err)
	} else if len(rs) == 0 {
		log.Fatal("undefined result", err)
	} else {
		var allow, ok bool
		var denyReason string
		if allow, ok = rs[0].Bindings["x"].(map[string]interface{})["allow"].(bool); !ok {
			log.Fatalf("unexpected result type: %v", rs[0].Bindings["x"].(map[string]interface{})["allow"])
		}
		if denyReason, ok = rs[0].Bindings["x"].(map[string]interface{})["denyReason"].(string); !ok {
			log.Fatalf("unexpected result type: %v", rs[0].Bindings["x"].(map[string]interface{})["denyReason"])
		}
		result = evalResult{allow, denyReason}
		log.Printf("%+v %+v\n", allow, denyReason)
	}

	return result, nil
}
