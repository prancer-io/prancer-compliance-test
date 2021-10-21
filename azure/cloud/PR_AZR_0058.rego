#
# PR-AZR-0058
#

package rule

default rulepass = false

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2017-03-01-preview/servers/databases/vulnerabilityassessments

rulepass {
    lower(input.type) == "microsoft.sql/servers/databases/vulnerabilityassessments"
    input.properties.recurringScans.isEnabled == true
}

metadata := {
    "Policy Code": "PR-AZR-0058",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "Cloud",
    "Policy Title": "Azure SQL Server advanced data security is disabled",
    "Policy Description": "Advanced data security (ADS) provides a set of advanced SQL security capabilities, including vulnerability assessment, threat detection, and data discovery and classification.<br><br>This policy identifies Azure SQL servers that do not have ADS enabled. As a best practice, enable ADS on mission-critical SQL servers.",
    "Resource Type": "microsoft.sql/servers/databases/vulnerabilityassessments",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2017-03-01-preview/servers/databases/vulnerabilityassessments"
}
