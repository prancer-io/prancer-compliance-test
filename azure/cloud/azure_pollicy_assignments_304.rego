package rule
default rulepass = true

# System updates is set to OFF in Security Center
# If System updates is set to ON in Security Center test will pass
# System updates on virtual machine scale sets should be installed

# https://docs.microsoft.com/en-us/rest/api/resources/policyassignments/list#code-try-0

rulepass = false {                                      
   count(system_updates) == 1
}

#  properties.parameters.systemUpdatesMonitoringEffect.value 

system_updates["system_updates_access_set_on"] {
   input.properties.parameters.systemUpdatesMonitoringEffect.value = "Disabled"
}