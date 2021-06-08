#
# PR-AZR-0076
#

package rule
default rulepass = false

# Disk encryption is set to OFF in Security Center
# If Disk encryption is set to ON in Security Center

# https://docs.microsoft.com/en-us/rest/api/resources/policyassignments/list#code-try-0

rulepass {
    lower(input.type) == "microsoft.authorization/policyassignments"
    contains(input.id, "diskEncryptionMonitoring")
}

metadata := {
    "Policy Code": "PR-AZR-0076",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "Cloud",
    "Policy Title": "Disk encryption is set to OFF in Security Center",
    "Policy Description": "Turning on Disk encryption for virtual machines will secure the data by encrypting it.",
    "Compliance": ["CIS","CSA-CCM","HIPAA","ISO 27001","NIST 800","PCI-DSS"],
    "Resource Type": "microsoft.authorization/policyassignments",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/rest/api/resources/policyassignments/list#code-try-0"
}
