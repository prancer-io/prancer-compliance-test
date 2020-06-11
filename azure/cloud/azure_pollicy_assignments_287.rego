package rule
default rulepass = true

# JIT Network Access is set to OFF in Security Center
# If JIT Network Access is set to ON in Security Center

# https://docs.microsoft.com/en-us/rest/api/resources/policyassignments/list#code-try-0

rulepass = false {                                      
   count(just_in_time_network_access) == 1
}

#  properties.parameters.jitNetworkAccessMonitoringEffect.value 

just_in_time_network_access["just_in_time_network_access_set_on"] {
   input.properties.parameters.jitNetworkAccessMonitoringEffect.value = "Disabled"
}