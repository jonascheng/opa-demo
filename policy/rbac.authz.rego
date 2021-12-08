# Write rules that make policy decisions. A rule is a conditional assignment.
# Organise rules into policies. A policy is a set of rules with a hierarchical name
# [Playground](https://play.openpolicyagent.org/)

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
	g = input.grantedGroups[_]
	g == input.group
}
