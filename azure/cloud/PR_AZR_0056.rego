#
# PR-AZR-0056
#

package rule

default rulepass = false

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2017-03-01-preview/servers/databases/vulnerabilityassessments

rulepass {
    lower(input.type) == "microsoft.sql/servers/databases/vulnerabilityassessments"
    input.properties.recurringScans.isEnabled == true
    input.properties.recurringScans.emailSubscriptionAdmins == true
    count(input.properties.recurringScans.emails) > 0
}

metadata := {
    "Policy Code": "PR-AZR-0056",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "Cloud",
    "Policy Title": "Azure SQL Server advanced data security does not have an email alert recipient",
    "Policy Description": "Advanced data security (ADS) provides a set of advanced SQL security capabilities, including vulnerability assessment, threat detection, and data discovery and classification._x005F_x000D_ _x005F_x000D_ This policy identifies Azure SQL Servers that do not have an email address configured for ADS alert notifications. As a best practice, provide one or more email addresses where you want to receive alerts for any anomalous activities detected on SQL Servers.",
    "Resource Type": "microsoft.sql/servers/databases/vulnerabilityassessments",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2017-03-01-preview/servers/databases/vulnerabilityassessments"
}
