# opa-demo

[![Run Tests](https://github.com/jonascheng/opa-demo/actions/workflows/go.yml/badge.svg)](https://github.com/jonascheng/opa-demo/actions/workflows/go.yml)
[![Open Policy Agent Testing](https://github.com/jonascheng/opa-demo/actions/workflows/opa.yml/badge.svg)](https://github.com/jonascheng/opa-demo/actions/workflows/opa.yml)

How to use Role-based access control (RBAC) with the Open Policy Agent. See the [reference guide](https://www.openpolicyagent.org/docs/latest/comparison-to-other-systems/#role-based-access-control-rbac).

## Integrating with the Go API

### Create RBAC policy

[embedmd]:# (policy/rbac.authz.rego)
```rego
package rbac.authz

# user-role assignments
user_roles := {
	"default-admin": ["default-admin", "admin"],
	"admin": ["admin"],
	"operator": ["operator"],
	"viewer": ["viewer"],
}

# role-permissions assignments
role_permissions := {
	"admin": [
		# stellarone system configurations
		{"action": "view", "object": "system-configurations"},
		{"action": "edit", "object": "system-configurations"},
		# manage all groups
		{"action": "create", "object": "agent-groups"},
		{"action": "view", "object": "agent-groups"},
		{"action": "edit", "object": "agent-groups"},
		{"action": "delete", "object": "agent-groups"},
		# manage all accounts
		{"action": "create", "object": "system-accounts"},
		{"action": "view", "object": "system-accounts"},
		{"action": "edit", "object": "system-accounts"},
		{"action": "delete", "object": "system-accounts"},
		# manage policy configurations
		{"action": "create", "object": "agent-policies"},
		{"action": "view", "object": "agent-policies"},
		{"action": "edit", "object": "agent-policies"},
		{"action": "delete", "object": "agent-policies"},
	],
	"operator": [
		# manage assigned groups
		{"action": "create", "object": "agent-groups"},
		{"action": "view", "object": "agent-groups"},
		{"action": "edit", "object": "agent-groups"},
		{"action": "delete", "object": "agent-groups"},
		# manage policy configurations
		{"action": "create", "object": "agent-policies"},
		{"action": "view", "object": "agent-policies"},
		{"action": "edit", "object": "agent-policies"},
		{"action": "delete", "object": "agent-policies"},
	],
	"viewer": [
		# manage assigned groups
		{"action": "view", "object": "agent-groups"},
		# manage policy configurations
		{"action": "view", "object": "agent-policies"},
	],
}

# role-group permissions assignments
role_group_permissions := {
  "default-admin": [
    	{"object": "all"},
    ],
	"admin": [
    	{"object": ""},
    ],
	"operator": [
    	{"object": ""},
    ],
	"viewer": [
    	{"object": ""},
    ],
}

# logic that implements RBAC.
default eval_result = {
		"allow": false,
		"denyReason": ""
	}

default allow = false

eval_result = result {
	result := {
		"allow": allow,
		"denyReason": deny_reason
	}
}

allow {
	is_action_permit_to_object
	is_group_permit_to_access
}

deny_reason = reason {
    not is_action_permit_to_object
    reason := "INVALID_ACTION_TO_OBJECT"
}

deny_reason = reason {
    not is_group_permit_to_access
    reason := "INVALID_ACCESS_TO_GROUP"
}

is_action_permit_to_object {
	# lookup the list of roles for the user
	roles := user_roles[input.role[_]]

	# for each role in that list
	r := roles[_]

	# lookup the permissions list for role r
	permissions := role_permissions[r]

	# for each permission
	p := permissions[_]

	# check if the permission granted to r matches the user's request
	p == {"action": input.action, "object": input.object}
}

is_group_permit_to_access {
	input.object != "agent-groups"
} else { # check group access
	# lookup the list of roles for the user
	roles := user_roles[input.role[_]]

	# for each role in that list
	r := roles[_]

	# lookup the permissions list for role r
	permissions := role_group_permissions[r]

	# for each permission
	p := permissions[_]

	# check if the permission granted to r matches the user's request
	p == {"object": "all"}
} else { # check group access
	# for each granted groups
	g = input.authzedGroups[_]
	g == input.group
}
```

### Write Testing

Please download [OPA Binary](https://www.openpolicyagent.org/docs/latest/#running-opa) first.

[embedmd]:# (policy/rbac.authz_test.rego)
```rego
package rbac.authz

test_default_admin {
	# stellarone system configurations
	not allow with input as {"role": ["default-admin"], "action": "create", "object": "system-configurations"}
	allow with input as {"role": ["default-admin"], "action": "view", "object": "system-configurations"}
	allow with input as {"role": ["default-admin"], "action": "edit", "object": "system-configurations"}
	not allow with input as {"role": ["default-admin"], "action": "delete", "object": "system-configurations"}
	# manage all groups
	allow with input as {"role": ["default-admin"], "action": "create", "object": "agent-groups"}
	allow with input as {"role": ["default-admin"], "action": "view", "object": "agent-groups"}
	allow with input as {"role": ["default-admin"], "action": "edit", "object": "agent-groups"}
	allow with input as {"role": ["default-admin"], "action": "delete", "object": "agent-groups"}
	allow with input as {"role": ["default-admin"], "action": "view", "object": "agent-groups", "group": "group1", "authzedGroups": []}
	allow with input as {"role": ["default-admin"], "action": "view", "object": "agent-groups", "group": "group1", "authzedGroups": ["group1", "group2", "group3"]}
	allow with input as {"role": ["default-admin"], "action": "view", "object": "agent-groups", "group": "group1", "authzedGroups": ["group3"]}
	# manage all accounts
	allow with input as {"role": ["default-admin"], "action": "create", "object": "system-accounts"}
	allow with input as {"role": ["default-admin"], "action": "view", "object": "system-accounts"}
	allow with input as {"role": ["default-admin"], "action": "edit", "object": "system-accounts"}
	allow with input as {"role": ["default-admin"], "action": "delete", "object": "system-accounts"}
	# manage policy configurations
	allow with input as {"role": ["default-admin"], "action": "create", "object": "agent-policies"}
	allow with input as {"role": ["default-admin"], "action": "view", "object": "agent-policies"}
	allow with input as {"role": ["default-admin"], "action": "edit", "object": "agent-policies"}
	allow with input as {"role": ["default-admin"], "action": "delete", "object": "agent-policies"}
}

test_admin {
	# stellarone system configurations
	not allow with input as {"role": ["admin"], "action": "create", "object": "system-configurations"}
	allow with input as {"role": ["admin"], "action": "view", "object": "system-configurations"}
	allow with input as {"role": ["admin"], "action": "edit", "object": "system-configurations"}
	not allow with input as {"role": ["admin"], "action": "delete", "object": "system-configurations"}
	# manage all groups
	not allow with input as {"role": ["admin"], "action": "create", "object": "agent-groups", "group": "group1", "authzedGroups": []}
	allow with input as {"role": ["admin"], "action": "create", "object": "agent-groups", "group": "group1", "authzedGroups": ["group1", "group2", "group3"]}
	not allow with input as {"role": ["admin"], "action": "create", "object": "agent-groups", "group": "group1", "authzedGroups": ["group3"]}
	not allow with input as {"role": ["admin"], "action": "view", "object": "agent-groups", "group": "group1", "authzedGroups": []}
	allow with input as {"role": ["admin"], "action": "view", "object": "agent-groups", "group": "group1", "authzedGroups": ["group1", "group2", "group3"]}
	not allow with input as {"role": ["admin"], "action": "view", "object": "agent-groups", "group": "group1", "authzedGroups": ["group3"]}
	not allow with input as {"role": ["admin"], "action": "edit", "object": "agent-groups", "group": "group1", "authzedGroups": []}
	allow with input as {"role": ["admin"], "action": "edit", "object": "agent-groups", "group": "group1", "authzedGroups": ["group1", "group2", "group3"]}
	not allow with input as {"role": ["admin"], "action": "edit", "object": "agent-groups", "group": "group1", "authzedGroups": ["group3"]}
	not allow with input as {"role": ["admin"], "action": "delete", "object": "agent-groups", "group": "group1", "authzedGroups": []}
	allow with input as {"role": ["admin"], "action": "delete", "object": "agent-groups", "group": "group1", "authzedGroups": ["group1", "group2", "group3"]}
	not allow with input as {"role": ["admin"], "action": "delete", "object": "agent-groups", "group": "group1", "authzedGroups": ["group3"]}
	# manage all accounts
	allow with input as {"role": ["admin"], "action": "create", "object": "system-accounts"}
	allow with input as {"role": ["admin"], "action": "view", "object": "system-accounts"}
	allow with input as {"role": ["admin"], "action": "edit", "object": "system-accounts"}
	allow with input as {"role": ["admin"], "action": "delete", "object": "system-accounts"}
	# manage policy configurations
	allow with input as {"role": ["admin"], "action": "create", "object": "agent-policies"}
	allow with input as {"role": ["admin"], "action": "view", "object": "agent-policies"}
	allow with input as {"role": ["admin"], "action": "edit", "object": "agent-policies"}
	allow with input as {"role": ["admin"], "action": "delete", "object": "agent-policies"}
}

test_operator {
	# stellarone system configurations
	not allow with input as {"role": ["operator"], "action": "create", "object": "system-configurations"}
	not allow with input as {"role": ["operator"], "action": "view", "object": "system-configurations"}
	not allow with input as {"role": ["operator"], "action": "edit", "object": "system-configurations"}
	not allow with input as {"role": ["operator"], "action": "delete", "object": "system-configurations"}
	# manage all groups
	not allow with input as {"role": ["operator"], "action": "create", "object": "agent-groups", "group": "group1", "authzedGroups": []}
	allow with input as {"role": ["operator"], "action": "create", "object": "agent-groups", "group": "group1", "authzedGroups": ["group1", "group2", "group3"]}
	not allow with input as {"role": ["operator"], "action": "create", "object": "agent-groups", "group": "group1", "authzedGroups": ["group3"]}
	not allow with input as {"role": ["operator"], "action": "view", "object": "agent-groups", "group": "group1", "authzedGroups": []}
	allow with input as {"role": ["operator"], "action": "view", "object": "agent-groups", "group": "group1", "authzedGroups": ["group1", "group2", "group3"]}
	not allow with input as {"role": ["operator"], "action": "view", "object": "agent-groups", "group": "group1", "authzedGroups": ["group3"]}
	not allow with input as {"role": ["operator"], "action": "edit", "object": "agent-groups", "group": "group1", "authzedGroups": []}
	allow with input as {"role": ["operator"], "action": "edit", "object": "agent-groups", "group": "group1", "authzedGroups": ["group1", "group2", "group3"]}
	not allow with input as {"role": ["operator"], "action": "edit", "object": "agent-groups", "group": "group1", "authzedGroups": ["group3"]}
	not allow with input as {"role": ["operator"], "action": "delete", "object": "agent-groups", "group": "group1", "authzedGroups": []}
	allow with input as {"role": ["operator"], "action": "delete", "object": "agent-groups", "group": "group1", "authzedGroups": ["group1", "group2", "group3"]}
	not allow with input as {"role": ["operator"], "action": "delete", "object": "agent-groups", "group": "group1", "authzedGroups": ["group3"]}
	# manage all accounts
	not allow with input as {"role": ["operator"], "action": "create", "object": "system-accounts"}
	not allow with input as {"role": ["operator"], "action": "view", "object": "system-accounts"}
	not allow with input as {"role": ["operator"], "action": "edit", "object": "system-accounts"}
	not allow with input as {"role": ["operator"], "action": "delete", "object": "system-accounts"}
	# manage policy configurations
	allow with input as {"role": ["operator"], "action": "create", "object": "agent-policies"}
	allow with input as {"role": ["operator"], "action": "view", "object": "agent-policies"}
	allow with input as {"role": ["operator"], "action": "edit", "object": "agent-policies"}
	allow with input as {"role": ["operator"], "action": "delete", "object": "agent-policies"}
}

test_viewer {
	# stellarone system configurations
	not allow with input as {"role": ["viewer"], "action": "create", "object": "system-configurations"}
	not allow with input as {"role": ["viewer"], "action": "view", "object": "system-configurations"}
	not allow with input as {"role": ["viewer"], "action": "edit", "object": "system-configurations"}
	not allow with input as {"role": ["viewer"], "action": "delete", "object": "system-configurations"}
	# manage all groups
	not allow with input as {"role": ["viewer"], "action": "create", "object": "agent-groups", "group": "group1", "authzedGroups": []}
	not allow with input as {"role": ["viewer"], "action": "create", "object": "agent-groups", "group": "group1", "authzedGroups": ["group1", "group2", "group3"]}
	not allow with input as {"role": ["viewer"], "action": "create", "object": "agent-groups", "group": "group1", "authzedGroups": ["group3"]}
	not allow with input as {"role": ["viewer"], "action": "view", "object": "agent-groups", "group": "group1", "authzedGroups": []}
  allow with input as {"role": ["viewer"], "action": "view", "object": "agent-groups", "group": "group1", "authzedGroups": ["group1", "group2", "group3"]}
	not allow with input as {"role": ["viewer"], "action": "view", "object": "agent-groups", "group": "group1", "authzedGroups": ["group3"]}
	not allow with input as {"role": ["viewer"], "action": "edit", "object": "agent-groups", "group": "group1", "authzedGroups": []}
	not allow with input as {"role": ["viewer"], "action": "edit", "object": "agent-groups", "group": "group1", "authzedGroups": ["group1", "group2", "group3"]}
	not allow with input as {"role": ["viewer"], "action": "edit", "object": "agent-groups", "group": "group1", "authzedGroups": ["group3"]}
	not allow with input as {"role": ["viewer"], "action": "delete", "object": "agent-groups", "group": "group1", "authzedGroups": []}
	not allow with input as {"role": ["viewer"], "action": "delete", "object": "agent-groups", "group": "group1", "authzedGroups": ["group1", "group2", "group3"]}
	not allow with input as {"role": ["viewer"], "action": "delete", "object": "agent-groups", "group": "group1", "authzedGroups": ["group3"]}
	# manage all accounts
	not allow with input as {"role": ["viewer"], "action": "create", "object": "system-accounts"}
	not allow with input as {"role": ["viewer"], "action": "view", "object": "system-accounts"}
	not allow with input as {"role": ["viewer"], "action": "edit", "object": "system-accounts"}
	not allow with input as {"role": ["viewer"], "action": "delete", "object": "system-accounts"}
	# manage policy configurations
	not allow with input as {"role": ["viewer"], "action": "create", "object": "agent-policies"}
	allow with input as {"role": ["viewer"], "action": "view", "object": "agent-policies"}
	not allow with input as {"role": ["viewer"], "action": "edit", "object": "agent-policies"}
	not allow with input as {"role": ["viewer"], "action": "delete", "object": "agent-policies"}
}
```

run test command:

```bash
$ opa test -v *.rego
data.rbac.authz.test_default_admin: PASS (14.983875ms)
data.rbac.authz.test_admin: PASS (10.832791ms)
data.rbac.authz.test_operator: PASS (6.172959ms)
data.rbac.authz.test_viewer: PASS (3.544875ms)
--------------------------------------------------------------------------------
PASS: 4/4
```
