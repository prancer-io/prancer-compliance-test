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

metadata := {
    "Policy Code": "PR-AZR-0049",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "Cloud",
    "Policy Title": "Azure Network Security Groups (NSG) is set to OFF in Security Center",
    "Policy Description": "Turning on Network Security Groups will identify the Network Security Groups which are not enabled. Network Security Groups are designed to control inbound and outbound traffic to VMs that have open endpoints.",
    "Compliance": ["CIS","CSA-CCM","ISO 27001","NIST 800","PCI-DSS"],
    "Resource Type": "microsoft.authorization/policyassignments",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/rest/api/resources/policyassignments/list#code-try-0"
}
