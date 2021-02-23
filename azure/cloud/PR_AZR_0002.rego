#
# PR-AZR-0002
#

package rule
default rulepass = false

# Adaptive Application Controls is set to OFF in Security Center
# If Adaptive Application Controls is set to ON in Security Center

# https://docs.microsoft.com/en-us/rest/api/resources/policyassignments/list#code-try-0

rulepass {
    input.type == "Microsoft.Authorization/policyAssignments"
    contains(input.id, "adaptiveApplicationControlsMonitoring")
}