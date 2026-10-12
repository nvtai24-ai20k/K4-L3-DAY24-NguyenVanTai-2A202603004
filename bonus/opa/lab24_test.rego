# Unit test cho lab24.rego: `opa test bonus/opa principals:data/principals.json -v`
package lab24.pep_test

import rego.v1

import data.lab24.pep

_ctx(changes) := object.union(
	{
		"data_classification": "restricted",
		"request_purpose": "support-reply",
		"agent_owner": "lab24-agent/run-b",
		"delegation_depth": 0,
		"egress_enabled": false,
		"principal_id": "dpo",
		"requested_tool": "read_customer",
		"agent_scopes": ["search_docs", "read_customer"],
		"parent_scopes": [],
		"expires_at": "2099-01-01T00:00:00+00:00",
	},
	changes,
)

test_restricted_egress_denied_even_for_dpo if {
	d := pep.decide(_ctx({"requested_tool": "http_post", "egress_enabled": true, "agent_scopes": ["http_post"]}))
	d.allow == false
	contains(d.reason, "restricted+egress")
}

test_support_l1_cannot_read_customer if {
	d := pep.decide(_ctx({"principal_id": "support_l1"}))
	d.allow == false
	d.reason != ""
}

test_dpo_can_read_for_valid_purpose if {
	d := pep.decide(_ctx({}))
	d.allow == true
	startswith(d.reason, "allow read_customer")
}

test_delegation_cannot_expand_parent_scope if {
	d := pep.decide(_ctx({"delegation_depth": 1, "parent_scopes": ["search_docs"]}))
	d.allow == false
	contains(d.reason, "parent_scopes")
}

test_expired_unknown_and_malformed_are_denied if {
	every changes in [
		{"expires_at": "2000-01-01T00:00:00+00:00"},
		{"expires_at": "not-a-date"},
		{"principal_id": "nobody"},
		{"principal_id": ""},
		{"data_classification": "secret"},
	] {
		d := pep.decide(_ctx(changes))
		d.allow == false
		d.reason != ""
	}
}

test_wrong_purpose_denied if {
	d := pep.decide(_ctx({"request_purpose": "billing-reconciliation"}))
	d.allow == false
	contains(d.reason, "purpose")
}

test_missing_input_is_default_deny if {
	d := pep.decision with input as {}
	d.allow == false
	d.reason != ""
}
