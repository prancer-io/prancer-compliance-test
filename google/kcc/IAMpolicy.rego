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
