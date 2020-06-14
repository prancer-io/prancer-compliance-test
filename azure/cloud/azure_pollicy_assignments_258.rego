package rule
default rulepass = true

# Azure Network Security Groups (NSG) is set to OFF in Security Center
# If Azure Network Security Groups (NSG) is set to ON in Security Center

# https://docs.microsoft.com/en-us/rest/api/resources/policyassignments/list#code-try-0

rulepass = false {                                      
   input.properties.parameters.networkSecurityGroupsOnVirtualMachinesMonitoringEffect.value == "Disabled"
}
