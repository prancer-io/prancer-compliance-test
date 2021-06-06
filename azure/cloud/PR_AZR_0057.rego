#
# PR-AZR-0057
#

package rule

default rulepass = false

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2017-03-01-preview/servers/databases/vulnerabilityassessments

rulepass {
    lower(input.type) == "microsoft.sql/servers/databases/vulnerabilityassessments"
    input.properties.recurringScans.isEnabled == true
    input.properties.recurringScans.emailSubscriptionAdmins == true
}

metadata := {
    "Policy Code": "PR-AZR-0057",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "Cloud",
    "Policy Title": "Azure SQL Server advanced data security does not send alerts to service and co-administrators",
    "Policy Description": "Advanced data security (ADS) provides a set of advanced SQL security capabilities, including vulnerability assessment, threat detection, and data discovery and classification._x005F_x000D_ _x005F_x000D_ This policy identifies Azure SQL Servers that are not enabled with ADS. As a best practice, enable ADS so that the administratorsâ€”service and co-administratorâ€”can receive email alerts when anomalous activities are detected on the SQL Servers.",
    "Resource Type": "microsoft.sql/servers/databases/vulnerabilityassessments",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2017-03-01-preview/servers/databases/vulnerabilityassessments"
}
