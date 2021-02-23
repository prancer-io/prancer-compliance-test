#
# PR-AZR-0313
#

package rule

default rulepass = false

# Policy rule definition
# https://github.com/Azure/azure-policy/blob/master/built-in-policies/policyDefinitions/Guest%20Configuration/GuestConfiguration_AddSystemIdentityWhenNone_Prerequisite.json

rulepass = true{
  elem := input.identity.type
  choices := "SystemAssigned"
  contains(choices, elem)
}


# Add err = "No system-assigned managed identity to enable Guest Configuration assignments on this virtual machine"
