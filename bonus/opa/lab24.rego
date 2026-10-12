# Bonus — port agent/policy.py::check sang Rego (OPA v1).
#
# Thứ tự rule giữ y như bản Python: rule tối thiểu restricted+egress đứng
# đầu (không quyền OBO nào gỡ được), sau đó classification, principal, TTL,
# quyền hiệu lực và purpose. Mọi nhánh đều trả reason non-empty.
#
# Principal nạp làm data với prefix:
#   opa eval -d bonus/opa/lab24.rego -d principals:data/principals.json ...
package lab24.pep

import rego.v1

classifications := {"public", "internal", "restricted"}

default decision := {"allow": false, "reason": "deny: OPA không ra được quyết định (default deny)"}

decision := decide(input) if input.data_classification

# Đánh giá nhiều context trong một lần gọi `opa eval` (dùng cho test parity).
batch := [_decide_or_default(c) | some c in input.contexts]

_decide_or_default(c) := d if {
	d := decide(c)
} else := {"allow": false, "reason": "deny: OPA không ra được quyết định (default deny)"}

_tool(c) := c.requested_tool if {
	c.requested_tool != ""
} else := "<tool?>"

_deny(c, msg) := {"allow": false, "reason": sprintf("deny %s: %s", [_tool(c), msg])}

_principal(c) := data.principals[c.principal_id]

# time.parse_rfc3339_ns lỗi -> undefined -> nhánh "expires_at không hợp lệ".
_expires_ns(c) := time.parse_rfc3339_ns(c.expires_at)

_set(arr) := {x | some x in arr}

_effective(c) := (_set(_principal(c).allowed_tools) & _set(c.agent_scopes)) & _set(c.parent_scopes) if {
	c.delegation_depth > 0
} else := _set(_principal(c).allowed_tools) & _set(c.agent_scopes)

_missing(c) := sprintf("principal %s không có quyền %s", [c.principal_id, _tool(c)]) if {
	not _tool(c) in _principal(c).allowed_tools
} else := sprintf("agent_scopes không gồm %s", [_tool(c)]) if {
	not _tool(c) in c.agent_scopes
} else := sprintf("parent_scopes không gồm %s (agent con không được vượt agent cha)", [_tool(c)])

_py_bool(b) := "True" if b == true

else := "False"

decide(c) := _deny(c, "dữ liệu restricted không được đi kèm egress (rule tối thiểu restricted+egress)") if {
	c.data_classification == "restricted"
	c.egress_enabled == true
} else := _deny(c, sprintf("classification không hợp lệ '%s'", [c.data_classification])) if {
	not c.data_classification in classifications
} else := _deny(c, "thiếu principal_id (không rõ hành động thay ai)") if {
	c.principal_id == ""
} else := _deny(c, sprintf("principal '%s' không có trong data/principals.json", [c.principal_id])) if {
	not _principal(c)
} else := _deny(c, "expires_at thiếu hoặc không phải ISO-8601 có timezone") if {
	not _expires_ns(c)
} else := _deny(c, sprintf("uỷ quyền đã hết hạn lúc %s", [c.expires_at])) if {
	_expires_ns(c) <= time.now_ns()
} else := {"allow": false, "reason": "deny: thiếu requested_tool"} if {
	c.requested_tool == ""
} else := _deny(c, "delegation_depth âm") if {
	c.delegation_depth < 0
} else := _deny(c, sprintf("ngoài quyền hiệu lực — %s", [_missing(c)])) if {
	not _tool(c) in _effective(c)
} else := _deny(c, sprintf("purpose '%s' không thuộc purposes của %s", [c.request_purpose, c.principal_id])) if {
	not c.request_purpose in _principal(c).purposes
} else := {"allow": true, "reason": sprintf(
	"allow %s: trong quyền hiệu lực của %s cho purpose '%s', classification=%s, egress=%s, hết hạn %s",
	[_tool(c), c.principal_id, c.request_purpose, c.data_classification, _py_bool(c.egress_enabled), c.expires_at],
)}
