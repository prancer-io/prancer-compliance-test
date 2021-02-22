#
# PR-AZR-0078
#

package rule
default rulepass = false

# JIT Network Access is set to OFF in Security Center
# If JIT Network Access is set to ON in Security Center

# https://docs.microsoft.com/en-us/rest/api/resources/policyassignments/list#code-try-0

rulepass {
    input.type == "Microsoft.Authorization/policyAssignments"
    contains(input.id, "jitNetworkAccessMonitoring")
}
