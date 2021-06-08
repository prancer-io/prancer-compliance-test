#
# PR-AZR-0055
#

package rule

default rulepass = false

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2018-06-01-preview/servers/databases/securityalertpolicies

rulepass {
    lower(input.type) == "microsoft.sql/servers/databases/securityalertpolicies"
    input.properties.state == "Enabled"
    input.properties.emailAccountAdmins == true
    count(input.properties.emailAddresses) > 0
}

metadata := {
    "Policy Code": "PR-AZR-0055",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "Cloud",
    "Policy Title": "Azure SQL Databases with disabled Email service and co-administrators for Threat Detection",
    "Policy Description": "This policy identifies SQL Databases which have disabled Email service and co-administrators for Threat Detection. Enable 'Email service and co-administrators' option to receive security alerts of any anomalous activities in SQL database. The alert notifications are sent to service and co-administrator email addresses so that they can mitigate any potential risks.",
    "Compliance": ["CSA-CCM","HIPAA","ISO 27001","NIST 800","PCI-DSS"],
    "Resource Type": "microsoft.sql/servers/databases/securityalertpolicies",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2018-06-01-preview/servers/databases/securityalertpolicies"
}
