package rule
default rulepass = true

# Disk encryption is set to OFF in Security Center
# If Disk encryption is set to ON in Security Center

# https://docs.microsoft.com/en-us/rest/api/resources/policyassignments/list#code-try-0

rulepass = false {                                      
   count(disk_encryption) == 1
}

#  properties.parameters.diskEncryptionMonitoringEffect.value 

disk_encryption["disk_encryption_set_on"] {
   input.properties.parameters.diskEncryptionMonitoringEffect.value = "Disabled"
}