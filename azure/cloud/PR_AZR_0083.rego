#
# PR-AZR-0083
#

package rule
default rulepass = false

# SQL auditing & Threat detection is set to OFF in Security Center
# If SQL auditing & Threat detection is set to ON in Security Center test will pass
# Auditing should be enabled on advanced data security settings on SQL server

# https://docs.microsoft.com/en-us/rest/api/resources/policyassignments/list#code-try-0

rulepass {
    lower(input.type) == "microsoft.authorization/policyassignments"
    contains(input.id, "sqlServerAuditingMonitoring")
}

metadata := {
    "Policy Code": "PR-AZR-0083",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "Cloud",
    "Policy Title": "SQL auditing PR-AZR-0083-TITLE Threat detection is set to OFF in Security Center",
    "Policy Description": "Turning on SQL auditing PR-AZR-0083-DESC Threat detection will make sure that the databases adhere to regulatory compliance. It will also help understand database activity, and gain insights into discrepancies and anomalies that could show business concerns or any security violations.",
    "Resource Type": "microsoft.authorization/policyassignments",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/rest/api/resources/policyassignments/list#code-try-0"
}
