package rule
default rulepass = true

# Storage Encryption is set to OFF in Security Center
# If Storage Encryption is set to OFF in Security Center test will pass
# Secure transfer to storage accounts should be enabled

# https://docs.microsoft.com/en-us/rest/api/resources/policyassignments/list#code-try-0

rulepass = false {                                      
   count(storage_encryption) >= 1
}

#  properties.parameters.secureTransferToStorageAccountMonitoringEffect.value 

storage_encryption["storage_encryption_access_set_on_dasabled"] {
   input.properties.parameters.secureTransferToStorageAccountMonitoringEffect.value == "Disabled"
}

storage_encryption["storage_encryption_access_set_on_dany"] {
   input.properties.parameters.secureTransferToStorageAccountMonitoringEffect.value == "Deny"
}
