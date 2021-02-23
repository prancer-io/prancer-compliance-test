#
# PR-AZR-0312
#

package rule

default rulepass = false

# Policy rule definition
# Audit Log Analytics agent deployment in virtual machine scale sets - VM Image (OS) unlisted
# https://github.com/Azure/azure-policy/blob/master/built-in-policies/policyDefinitions/Guest%20Configuration/GuestConfiguration_AddSystemIdentityWhenNone_Prerequisite.json

rulepass = true{
  input.type:= "Microsoft.Compute/virtualMachineScaleSets/extensions"
  # name:= "Microsoft.enterprisecloud"
  elem := input.properties.virtualMachineProfile.storageProfile.imageReference.publisher
  choices := ["MicrosoftWindowsServer","MicrosoftWindowsServer","MicrosoftSQLServer", "MicrosoftRServer", "MicrosoftVisualStudio",
  "MicrosoftDynamicsAX", "microsoft-ads", "MicrosoftWindowsDesktop", "RedHat", "SUSE", "Canonical", "Oracle", "OpenLogic"]
  some i
  elem = choices[i]
}

