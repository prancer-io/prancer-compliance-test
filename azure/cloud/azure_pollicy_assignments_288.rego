package rule
default rulepass = false

# Next generation firewall is set to OFF in Security Center
# If Next generation firewall is set to ON in Security Center test will pass
# access through internet facing endpoint should be restricted

# https://docs.microsoft.com/en-us/rest/api/resources/policyassignments/list#code-try-0

rulepass {
    contains(input.id, "nextGenerationFirewallMonitoring")
}
