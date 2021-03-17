#
# PR-AZR-0079
#

package rule
default rulepass = false

# Next generation firewall is set to OFF in Security Center
# If Next generation firewall is set to ON in Security Center test will pass
# access through internet facing endpoint should be restricted

# https://docs.microsoft.com/en-us/rest/api/resources/policyassignments/list#code-try-0

rulepass {
    lower(input.type) == "microsoft.authorization/policyassignments"
    contains(input.id, "nextGenerationFirewallMonitoring")
}
