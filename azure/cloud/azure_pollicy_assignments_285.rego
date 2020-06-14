package rule
default rulepass = true

# Disk encryption is set to OFF in Security Center
# If Disk encryption is set to ON in Security Center

# https://docs.microsoft.com/en-us/rest/api/resources/policyassignments/list#code-try-0

rulepass = false {                                      
   input.properties.parameters.diskEncryptionMonitoringEffect.value == "Disabled"
}
