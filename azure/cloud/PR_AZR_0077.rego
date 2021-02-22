#
# PR-AZR-0077
#

package rule
default rulepass = false

# Endpoint protection is set to OFF in Security Center
# If Endpoint protection is set to ON in Security Center

# https://docs.microsoft.com/en-us/rest/api/resources/policyassignments/list#code-try-0

rulepass {
    input.type == "Microsoft.Authorization/policyAssignments"
    contains(input.id, "vmssEndpointProtectionMonitoring")
}
