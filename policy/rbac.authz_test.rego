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
	allow with input as {"role": ["default-admin"], "action": "view", "object": "agent-groups", "group": "group1", "grantedGroups": []}
	allow with input as {"role": ["default-admin"], "action": "view", "object": "agent-groups", "group": "group1", "grantedGroups": ["group1", "group2", "group3"]}
	allow with input as {"role": ["default-admin"], "action": "view", "object": "agent-groups", "group": "group1", "grantedGroups": ["group3"]}
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
	not allow with input as {"role": ["admin"], "action": "create", "object": "agent-groups", "group": "group1", "grantedGroups": []}
	allow with input as {"role": ["admin"], "action": "create", "object": "agent-groups", "group": "group1", "grantedGroups": ["group1", "group2", "group3"]}
	not allow with input as {"role": ["admin"], "action": "create", "object": "agent-groups", "group": "group1", "grantedGroups": ["group3"]}
	not allow with input as {"role": ["admin"], "action": "view", "object": "agent-groups", "group": "group1", "grantedGroups": []}
	allow with input as {"role": ["admin"], "action": "view", "object": "agent-groups", "group": "group1", "grantedGroups": ["group1", "group2", "group3"]}
	not allow with input as {"role": ["admin"], "action": "view", "object": "agent-groups", "group": "group1", "grantedGroups": ["group3"]}
	not allow with input as {"role": ["admin"], "action": "edit", "object": "agent-groups", "group": "group1", "grantedGroups": []}
	allow with input as {"role": ["admin"], "action": "edit", "object": "agent-groups", "group": "group1", "grantedGroups": ["group1", "group2", "group3"]}
	not allow with input as {"role": ["admin"], "action": "edit", "object": "agent-groups", "group": "group1", "grantedGroups": ["group3"]}
	not allow with input as {"role": ["admin"], "action": "delete", "object": "agent-groups", "group": "group1", "grantedGroups": []}
	allow with input as {"role": ["admin"], "action": "delete", "object": "agent-groups", "group": "group1", "grantedGroups": ["group1", "group2", "group3"]}
	not allow with input as {"role": ["admin"], "action": "delete", "object": "agent-groups", "group": "group1", "grantedGroups": ["group3"]}
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
	not allow with input as {"role": ["operator"], "action": "create", "object": "agent-groups", "group": "group1", "grantedGroups": []}
	allow with input as {"role": ["operator"], "action": "create", "object": "agent-groups", "group": "group1", "grantedGroups": ["group1", "group2", "group3"]}
	not allow with input as {"role": ["operator"], "action": "create", "object": "agent-groups", "group": "group1", "grantedGroups": ["group3"]}
	not allow with input as {"role": ["operator"], "action": "view", "object": "agent-groups", "group": "group1", "grantedGroups": []}
	allow with input as {"role": ["operator"], "action": "view", "object": "agent-groups", "group": "group1", "grantedGroups": ["group1", "group2", "group3"]}
	not allow with input as {"role": ["operator"], "action": "view", "object": "agent-groups", "group": "group1", "grantedGroups": ["group3"]}
	not allow with input as {"role": ["operator"], "action": "edit", "object": "agent-groups", "group": "group1", "grantedGroups": []}
	allow with input as {"role": ["operator"], "action": "edit", "object": "agent-groups", "group": "group1", "grantedGroups": ["group1", "group2", "group3"]}
	not allow with input as {"role": ["operator"], "action": "edit", "object": "agent-groups", "group": "group1", "grantedGroups": ["group3"]}
	not allow with input as {"role": ["operator"], "action": "delete", "object": "agent-groups", "group": "group1", "grantedGroups": []}
	allow with input as {"role": ["operator"], "action": "delete", "object": "agent-groups", "group": "group1", "grantedGroups": ["group1", "group2", "group3"]}
	not allow with input as {"role": ["operator"], "action": "delete", "object": "agent-groups", "group": "group1", "grantedGroups": ["group3"]}
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
	not allow with input as {"role": ["viewer"], "action": "create", "object": "agent-groups", "group": "group1", "grantedGroups": []}
	not allow with input as {"role": ["viewer"], "action": "create", "object": "agent-groups", "group": "group1", "grantedGroups": ["group1", "group2", "group3"]}
	not allow with input as {"role": ["viewer"], "action": "create", "object": "agent-groups", "group": "group1", "grantedGroups": ["group3"]}
	not allow with input as {"role": ["viewer"], "action": "view", "object": "agent-groups", "group": "group1", "grantedGroups": []}
  allow with input as {"role": ["viewer"], "action": "view", "object": "agent-groups", "group": "group1", "grantedGroups": ["group1", "group2", "group3"]}
	not allow with input as {"role": ["viewer"], "action": "view", "object": "agent-groups", "group": "group1", "grantedGroups": ["group3"]}
	not allow with input as {"role": ["viewer"], "action": "edit", "object": "agent-groups", "group": "group1", "grantedGroups": []}
	not allow with input as {"role": ["viewer"], "action": "edit", "object": "agent-groups", "group": "group1", "grantedGroups": ["group1", "group2", "group3"]}
	not allow with input as {"role": ["viewer"], "action": "edit", "object": "agent-groups", "group": "group1", "grantedGroups": ["group3"]}
	not allow with input as {"role": ["viewer"], "action": "delete", "object": "agent-groups", "group": "group1", "grantedGroups": []}
	not allow with input as {"role": ["viewer"], "action": "delete", "object": "agent-groups", "group": "group1", "grantedGroups": ["group1", "group2", "group3"]}
	not allow with input as {"role": ["viewer"], "action": "delete", "object": "agent-groups", "group": "group1", "grantedGroups": ["group3"]}
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
