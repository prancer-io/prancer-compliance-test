package rule
default rulepass = true

# Security Configurations is set to OFF in Security Center
# If Security Configurations is set to ON in Security Center test will pass
# Vulnerabilities in container security configurations should be remediated 

# https://docs.microsoft.com/en-us/rest/api/resources/policyassignments/list#code-try-0

rulepass = false {                                      
   count(security_configurations) == 1
}

#  properties.parameters.containerBenchmarkMonitoringEffect.value 

security_configurations["security_configurations_access_set_on"] {
   input.properties.parameters.containerBenchmarkMonitoringEffect.value = "Disabled"
}