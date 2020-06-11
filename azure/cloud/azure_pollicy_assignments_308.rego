package rule
default rulepass = true

# Vulnerability assessment is set to OFF in Security Center
# If Vulnerability assessment is set to ON in Security Center test will pass
# Vulnerabilities should be remediated by a Vulnerability Assessment solution

# https://docs.microsoft.com/en-us/rest/api/resources/policyassignments/list#code-try-0

rulepass = false {                                      
   count(vulnerability_assessment) == 1
}

#  properties.parameters.jitNetworkAccessMonitoringEffect.value 

vulnerability_assessment["vulnerability_assessment_access_set_on"] {
   input.properties.parameters.vulnerabilityAssesmentMonitoringEffect.value = "Disabled"
}