package rule
default rulepass = true

# Endpoint protection is set to OFF in Security Center
# If Endpoint protection is set to ON in Security Center

# https://docs.microsoft.com/en-us/rest/api/resources/policyassignments/list#code-try-0

rulepass = false {                                      
   count(endpoint_protection) >= 1
}

#  properties.parameters.vmssEndpointProtectionMonitoringEffect.value 
#  properties.parameters.EndpointProtectionMonitoringEffect.value 

endpoint_protection["vmss_endpoint_protection_set_on"] {
   input.properties.parameters.vmssEndpointProtectionMonitoringEffect.value == "Disabled"
}

endpoint_protection["endpoint_protection_set_on"] {
   input.properties.parameters.endpointProtectionMonitoringEffect.value == "Disabled"
}
