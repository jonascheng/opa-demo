package main

import (
	"context"
	"log"
	"os"
	"testing"

	"github.com/jonascheng/opa-demo/policy"

	"github.com/open-policy-agent/opa/rego"
)

var query rego.PreparedEvalQuery

func setup() {
	var err error
	p, err := policy.ReadPolicy(policyPath)
	if err != nil {
		log.Fatal(err)
	}

	query, err = rego.New(
		rego.Query(defaultQuery),
		rego.Module(policyPath, string(p)),
	).PrepareForEval(context.TODO())

	if err != nil {
		log.Fatalf("initial rego error: %v", err)
	}
}

func TestMain(m *testing.M) {
	setup()
	code := m.Run()
	os.Exit(code)
}

func Test_result(t *testing.T) {
	ctx := context.TODO()
	type args struct {
		ctx   context.Context
		query rego.PreparedEvalQuery
		input map[string]interface{}
	}
	tests := []struct {
		name    string
		args    args
		want    evalResult
		wantErr evalResult
	}{
		{
			name: "test_default_admin_view_group",
			args: args{
				ctx:   ctx,
				query: query,
				input: map[string]interface{}{
					"role":   []string{"default-admin"},
					"action": "view",
					"object": "agent-groups",
				},
			},
			want: evalResult{true, nil},
		},
		{
			name: "test_admin_edit_system_configurations",
			args: args{
				ctx:   ctx,
				query: query,
				input: map[string]interface{}{
					"role":   []string{"admin"},
					"action": "edit",
					"object": "system-configurations",
				},
			},
			want: evalResult{true, nil},
		},
		{
			name: "test_admin_view_group",
			args: args{
				ctx:   ctx,
				query: query,
				input: map[string]interface{}{
					"role":          []string{"admin"},
					"action":        "view",
					"object":        "agent-groups",
					"group":         "group10",
					"authzedGroups": []string{"group1", "group2", "group3"},
				},
			},
			want: evalResult{false, []string{"INVALID_ACCESS_TO_GROUP"}},
		},
		{
			name: "test_viewer_edit_system_configurations",
			args: args{
				ctx:   ctx,
				query: query,
				input: map[string]interface{}{
					"role":   []string{"viewer"},
					"action": "edit",
					"object": "system-configurations",
				},
			},
			want: evalResult{false, []string{"INVALID_ACTION_TO_OBJECT"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := eval(tt.args.ctx, tt.args.query, tt.args.input)
			if got.Allow != tt.want.Allow {
				t.Errorf("result() = %v, want %v", got, tt.want)
			}
			for idx, reason := range got.DenyReason {
				if reason != tt.want.DenyReason[idx] {
					t.Errorf("result() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}
