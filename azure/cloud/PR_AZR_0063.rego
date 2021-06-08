#
# PR-AZR-0063
#

package rule
default rulepass = false

# https://docs.microsoft.com/en-us/azure/templates/microsoft.insights/2017-05-01-preview/diagnosticsettings

rulepass {
    lower(input.type) == "microsoft.insights/diagnosticsettings"
    logs := input.properties.logs[_]
    logs.category == "AuditEvent"
    logs.enabled == true
    logs.retentionPolicy.enabled == true
    logs.retentionPolicy.days >= 90
}

metadata := {
    "Policy Code": "PR-AZR-0063",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "Cloud",
    "Policy Title": "Azure Storage Account with Auditing Retention less than 90 days (TJX)",
    "Policy Description": "This policy identifies Storage Accounts which have Auditing Retentions less than 90 days. Audit Logs can be used to check for anomalies and gives insight into suspected breaches or misuse of information and access. It is recommended to configure Storage Account Audit Log Retention to be greater than or equal to 90 days.",
    "Compliance": [],
    "Resource Type": "microsoft.insights/diagnosticsettings",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.insights/2017-05-01-preview/diagnosticsettings"
}
