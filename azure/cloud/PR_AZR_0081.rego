#
# PR-AZR-0081
#

package rule
default rulepass = false

# SQL Encryption is set to OFF in Security Center
# If SQL Encryption is set to ON in Security Center test will pass
# Transparent Data Encryption on SQL databases should be enabled

# https://docs.microsoft.com/en-us/rest/api/resources/policyassignments/list#code-try-0

rulepass {
    lower(input.type) == "microsoft.authorization/policyassignments"
    contains(input.id, "sqlDbEncryptionMonitoring")
}

metadata := {
    "Policy Code": "PR-AZR-0081",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "Cloud",
    "Policy Title": "SQL Encryption is set to OFF in Security Center",
    "Policy Description": "Turning on SQL Encryption enables encryption at rest for your SQL database, related backups, and transaction log files. This will make sure that even if the database is compromised, the data is not readable.",
    "Resource Type": "microsoft.authorization/policyassignments",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/rest/api/resources/policyassignments/list#code-try-0"
}
