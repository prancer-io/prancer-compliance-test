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
    contains(input.id, "secureTransferToStorageAccountMonitoring")
}
