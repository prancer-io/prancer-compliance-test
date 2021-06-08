#
# PR-AZR-0061
#

package rule

default rulepass = false

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2017-03-01-preview/servers/securityalertpolicies

rulepass {
    lower(input.type) == "microsoft.sql/servers/databases/securityalertpolicies"
    input.properties.state == "Enabled"
    count(input.properties.disabledAlerts) == 0
}

metadata := {
    "Policy Code": "PR-AZR-0061",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "Cloud",
    "Policy Title": "Azure SQL Server threat detection alerts not enabled for all threat types",
    "Policy Description": "Advanced data security (ADS) provides a set of advanced SQL security capabilities, including vulnerability assessment, threat detection, and data discovery and classification._x005F_x000D_ _x005F_x000D_ This policy identifies Azure SQL servers that have disabled the detection of one or more threat types. To protect your SQL Servers, as a best practice, enable ADS detection for all types of threats.",
    "Compliance": [],
    "Resource Type": "microsoft.sql/servers/databases/securityalertpolicies",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2017-03-01-preview/servers/securityalertpolicies"
}
