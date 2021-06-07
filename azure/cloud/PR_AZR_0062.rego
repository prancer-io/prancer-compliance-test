#
# PR-AZR-0062
#

package rule

default rulepass = false

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2017-03-01-preview/servers/securityalertpolicies

rulepass {
    lower(input.type) == "microsoft.sql/servers/databases/securityalertpolicies"
    input.properties.state == "Enabled"
    input.properties.retentionDays > 90
}

metadata := {
    "Policy Code": "PR-AZR-0062",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "Cloud",
    "Policy Title": "Azure SQL Server threat logs retention is less than 91 days",
    "Policy Description": "This policy identifies SQL servers for which threat detection logs are retained for 90 days or less. Because threat detection logs help you investigate suspicious activities including detecting an SQL Server breach with known attack signatures, as a best practice, set the log retention period to more than 90 days.",
    "Resource Type": "microsoft.sql/servers/databases/securityalertpolicies",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2017-03-01-preview/servers/securityalertpolicies"
}
