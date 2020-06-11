package rule
default rulepass = true

# Azure Network Security Groups (NSG) is set to OFF in Security Center
# If Azure Network Security Groups (NSG) is set to ON in Security Center

# https://docs.microsoft.com/en-us/rest/api/resources/policyassignments/list#code-try-0

rulepass = false {                                      
   count(network_security_groups) == 1
}

# properties.parameters.networkSecurityGroupsOnVirtualMachinesMonitoringEffect.value 

network_security_groups["web_application_firewall_set_on"] {
   input.properties.parameters.networkSecurityGroupsOnVirtualMachinesMonitoringEffect.value = "Disabled"
}