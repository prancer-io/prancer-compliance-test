package rule
default rulepass = false

# Vulnerability assessment is set to OFF in Security Center
# If Vulnerability assessment is set to ON in Security Center test will pass
# Vulnerabilities should be remediated by a Vulnerability Assessment solution

# https://docs.microsoft.com/en-us/rest/api/resources/policyassignments/list#code-try-0

rulepass {
    contains(input.id, "vulnerabilityAssesmentMonitoring")
}
