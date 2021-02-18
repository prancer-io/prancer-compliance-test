#
# PR-AZR-0093
#

package rule

default rulepass = false

# Storage Accounts without their firewalls enabled (TJX)
# If Storage Accounts firewalls enabled testcase will pass

# https://resources.azure.com/subscriptions/db3667b7-cef9-4523-8e45-e2d9ed4518ab/resourceGroups/hardikResourceGroup/providers/Microsoft.Storage/storageAccounts/vatsalstorage1
# https://docs.microsoft.com/en-us/rest/api/storagerp/storageaccounts/getproperties

rulepass {
   input.properties.networkAcls.defaultAction == "Deny"
}
