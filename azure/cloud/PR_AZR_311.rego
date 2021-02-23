#
# PR-AZR-0311
#

package rule

default rulepass = false

# Policy rule definition
# https://github.com/Azure/azure-policy/blob/master/built-in-policies/policyDefinitions/Guest%20Configuration/GuestConfiguration_AddSystemIdentityWhenNone_Prerequisite.json
# Managed identities
# https://docs.microsoft.com/en-gb/azure/active-directory/managed-identities-azure-resources/tutorial-linux-vm-access-arm
# https://docs.microsoft.com/en-gb/azure/active-directory/managed-identities-azure-resources/tutorial-windows-vm-access-arm

rulepass = true{
    input.type = "Microsoft.Compute/virtualMachines"
    elem := input.identity.type
    choices := "SystemAssigned, UserAssigned"
    contains(choices, elem)
}
