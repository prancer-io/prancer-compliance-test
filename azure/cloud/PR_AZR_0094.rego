#
# PR-AZR-0094
#

package rule
default rulepass = false

# Storage Encryption is set to OFF in Security Center
# If Storage Encryption is set to OFF in Security Center test will pass
# Secure transfer to storage accounts should be enabled

# https://docs.microsoft.com/en-us/rest/api/resources/policyassignments/list#code-try-0

rulepass {
    lower(input.type) == "microsoft.authorization/policyassignments"
    contains(input.id, "secureTransferToStorageAccountMonitoring")
}

metadata := {
    "Policy Code": "PR-AZR-0094",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "Cloud",
    "Policy Title": "Storage Encryption is set to OFF in Security Center",
    "Policy Description": "Turning on Storage Encryption will encrypt the data written to the storage and decrypt it when retrieved from the storage. The data encryption starts from the point this setting is turned on. The old data remains unencrypted.",
    "Resource Type": "microsoft.authorization/policyassignments",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/rest/api/resources/policyassignments/list#code-try-0"
}
