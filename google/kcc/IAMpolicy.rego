package rule

# https://cloud.google.com/config-connector/docs/reference/resource-docs/iam/iampolicy

#
# AUDIT_LOGGING_DISABLED
#

default audit_logging_disabled = null

gc_issue["audit_logging_disabled"] {
    lower(input.kind) == "iampolicy"
    count([c | input.spec.auditConfigs[_].auditLogConfigs; c := 1]) == 0
}

audit_logging_disabled {
    lower(input.kind) == "iampolicy"
    not gc_issue["audit_logging_disabled"]
}

audit_logging_disabled = false {
    gc_issue["audit_logging_disabled"]
}

audit_logging_disabled_err = "Audit logging has been disabled for this resource." {
    gc_issue["audit_logging_disabled"]
}

audit_logging_disabled_metadata := {
    "Policy Code": "AUDIT_LOGGING_DISABLED",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "KCC",
    "Policy Title": "Audit Logging Disabled",
    "Policy Description": "Audit logging has been disabled for this resource.",
    "Resource Type": "IAMPolicy",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/config-connector/docs/reference/resource-docs/iam/iampolicy"
}

#
# PRIMITIVE_ROLES_USED
#

default primitive_roles_used = null

gc_issue["primitive_roles_used"] {
    lower(input.kind) == "iampolicy"
    lower(input.spec.bindings[_].role) == "roles/owner"
}

gc_issue["primitive_roles_used"] {
    lower(input.kind) == "iampolicy"
    lower(input.spec.bindings[_].role) == "roles/writer"
}

gc_issue["primitive_roles_used"] {
    lower(input.kind) == "iampolicy"
    lower(input.spec.bindings[_].role) == "roles/reader"
}

primitive_roles_used {
    lower(input.kind) == "iampolicy"
    not gc_issue["primitive_roles_used"]
}

primitive_roles_used = false {
    gc_issue["primitive_roles_used"]
}

primitive_roles_used_err = "A user has the basic role, Owner, Writer, or Reader. These roles are too permissive and shouldn't be used." {
    gc_issue["primitive_roles_used"]
}

primitive_roles_used_metadata := {
    "Policy Code": "PRIMITIVE_ROLES_USED",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "KCC",
    "Policy Title": "Primitive Roles Used",
    "Policy Description": "A user has the basic role, Owner, Writer, or Reader. These roles are too permissive and shouldn't be used.",
    "Resource Type": "IAMPolicy",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/config-connector/docs/reference/resource-docs/iam/iampolicy"
}

#
# REDIS_ROLE_USED_ON_ORG
#

default redis_role_used_on_org = null

gc_issue["redis_role_used_on_org"] {
	lower(input.kind) == "iampolicy"
    regex.match("^(project|folder)$", lower(input.spec.resourceRef.kind))
    lower(input.spec.bindings[_].role) == "roles/redis.admin"
}

gc_issue["redis_role_used_on_org"] {
	lower(input.kind) == "iampolicy"
    regex.match("^(project|folder)$", lower(input.spec.resourceRef.kind))
    lower(input.spec.bindings[_].role) == "roles/redis.editor"
}

gc_issue["redis_role_used_on_org"] {
	lower(input.kind) == "iampolicy"
    regex.match("^(project|folder)$", lower(input.spec.resourceRef.kind))
    lower(input.spec.bindings[_].role) == "roles/redis.viewer"
}

redis_role_used_on_org {
    lower(input.kind) == "iampolicy"
    not gc_issue["redis_role_used_on_org"]
}

redis_role_used_on_org = false {
    gc_issue["redis_role_used_on_org"]
}

redis_role_used_on_org_err = "A Redis IAM role is assigned at the organization or folder level." {
    gc_issue["redis_role_used_on_org"]
}

redis_role_used_on_org_metadata := {
    "Policy Code": "REDIS_ROLE_USED_ON_ORG",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "KCC",
    "Policy Title": "Redis Role Used On Org",
    "Policy Description": "A Redis IAM role is assigned at the organization or folder level.",
    "Resource Type": "IAMPolicy",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/config-connector/docs/reference/resource-docs/iam/iampolicy"
}
