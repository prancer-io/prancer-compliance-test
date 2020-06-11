package rule
default rulepass = true

# Next generation firewall is set to OFF in Security Center
# If Next generation firewall is set to ON in Security Center test will pass
# access through internet facing endpoint should be restricted

# https://docs.microsoft.com/en-us/rest/api/resources/policyassignments/list#code-try-0

rulepass = false {                                      
   count(next_generation_firewall) == 1
}

#  properties.parameters.nextGenerationFirewallMonitoringEffect.value 

next_generation_firewall["next_generation_firewall_access_set_on"] {
   input.properties.parameters.nextGenerationFirewallMonitoringEffect.value = "Disabled"
}