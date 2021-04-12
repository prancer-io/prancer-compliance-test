#
# PR-AZR-0086
#

package rule
default rulepass = false

# Security Configurations is set to OFF in Security Center
# If Security Configurations is set to ON in Security Center test will pass
# Vulnerabilities in container security configurations should be remediated

# https://docs.microsoft.com/en-us/rest/api/resources/policyassignments/list#code-try-0

rulepass {
    lower(input.type) == "microsoft.authorization/policyassignments"
    contains(input.id, "containerBenchmarkMonitoring")
}
