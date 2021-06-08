#
# PR-AZR-0088
#

package rule

default rulepass = false

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2017-03-01-preview/servers/databases/auditingsettings

rulepass {
    lower(input.type) == "microsoft.sql/servers/databases/auditingsettings"
    input.properties.state == "Enabled"
    input.properties.emailAccountAdmins == true
}

metadata := {
    "Policy Code": "PR-AZR-0088",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "Cloud",
    "Policy Title": "Send alerts on field value on SQL Databases is misconfigured",
    "Policy Description": "Checks to ensure that an valid email address is set for Threat Detection alerts. The alerts are sent to this email address when any anomalous activities are detected on SQL databases.",
    "Compliance": ["CIS","CSA-CCM","HIPAA","ISO 27001","NIST 800","PCI-DSS"],
    "Resource Type": "microsoft.sql/servers/databases/auditingsettings",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2017-03-01-preview/servers/databases/auditingsettings"
}
