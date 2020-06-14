package rule
default rulepass = true

# Web application firewall is set to OFF in Security Center
# If Web application firewall is set to ON in Security Center test will pass
# web ports should be restricted on network Security Groups associated to your VM

# https://docs.microsoft.com/en-us/rest/api/resources/policyassignments/list#code-try-0

rulepass = false {                                      
   input.properties.parameters.webApplicationFirewallMonitoringEffect.value == "Disabled"
}
