#
# PR-AZR-0059
#

package rule

default rulepass = false

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2017-03-01-preview/servers/auditingsettings

rulepass {
    lower(input.type) == "microsoft.sql/servers/databases/auditingsettings"
    input.properties.state == "Enabled"
    input.properties.retentionDays > 90
}

metadata := {
    "Policy Code": "PR-AZR-0059",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "Cloud",
    "Policy Title": "Azure SQL Server audit log retention is less than 91 days",
    "Policy Description": "Audit Logs can help you find suspicious events, unusual activity, and trends. Auditing the SQL server, at the server-level, allows you to track all existing and newly created databases on the instance.</br> </br> This policy identifies SQL servers which do not retain audit logs for more than 90 days. As a best practice, configure the audit logs retention time period to be greater than 90 days.",
    "Resource Type": "microsoft.sql/servers/databases/auditingsettings",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2017-03-01-preview/servers/auditingsettings"
}
