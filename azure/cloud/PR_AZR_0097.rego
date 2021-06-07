#
# PR-AZR-0097
#

package rule

default rulepass = false

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2018-06-01-preview/servers/databases/securityalertpolicies

rulepass {
    lower(input.type) == "microsoft.sql/servers/databases/securityalertpolicies"
    input.properties.state == "Enabled"
    count(input.properties.disabledAlerts) == 0
}

metadata := {
    "Policy Code": "PR-AZR-0097",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "Cloud",
    "Policy Title": "Threat Detection types on SQL databases is misconfigured",
    "Policy Description": "Ensure that Threat Detection types is set to All",
    "Resource Type": "microsoft.sql/servers/databases/securityalertpolicies",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2018-06-01-preview/servers/databases/securityalertpolicies"
}
