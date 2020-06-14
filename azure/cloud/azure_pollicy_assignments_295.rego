package rule
default rulepass = true

# Security Configurations is set to OFF in Security Center
# If Security Configurations is set to ON in Security Center test will pass
# Vulnerabilities in container security configurations should be remediated 

# https://docs.microsoft.com/en-us/rest/api/resources/policyassignments/list#code-try-0

rulepass = false {                                      
   input.properties.parameters.containerBenchmarkMonitoringEffect.value == "Disabled"
}
