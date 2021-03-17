#
# PR-AZR-0049
#

package rule
default rulepass = false

# Azure Network Security Groups (NSG) is set to OFF in Security Center
# If Azure Network Security Groups (NSG) is set to ON in Security Center

# https://docs.microsoft.com/en-us/rest/api/resources/policyassignments/list#code-try-0

rulepass {
    lower(input.type) == "microsoft.authorization/policyassignments"
    contains(input.id, "networkSecurityGroupsOnVirtualMachinesMonitoring")
}
