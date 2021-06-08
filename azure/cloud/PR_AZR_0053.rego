#
# PR-AZR-0053
#

package rule

default rulepass = false

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2017-03-01-preview/servers/databases/auditingsettings

rulepass {
    lower(input.type) == "microsoft.sql/servers/databases/auditingsettings"
    input.properties.state == "Enabled"
    input.properties.retentionDays >= 90
}

metadata := {
    "Policy Code": "PR-AZR-0053",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "Cloud",
    "Policy Title": "Azure SQL Database with Auditing Retention less than 90 days",
    "Policy Description": "This policy identifies SQL Databases which have Auditing Retention less than 90 days. Audit Logs can be used to check for anomalies and gives insight into suspected breaches or misuse of information and access. It is recommended to configure SQL database Audit Retention to be greater than or equal to 90 days.",
    "Compliance": ["CIS","CSA-CCM","HIPAA","ISO 27001","NIST 800","PCI-DSS"],
    "Resource Type": "microsoft.sql/servers/databases/auditingsettings",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2017-03-01-preview/servers/databases/auditingsettings"
}
