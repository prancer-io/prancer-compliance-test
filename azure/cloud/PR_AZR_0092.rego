#
# PR-AZR-0092
#

package rule

default rulepass = false

# Azure disk for VM operating system is not encrypted at rest using ADE
# If availability set is enabled test will pass

# https://resources.azure.com/subscriptions/db3667b7-cef9-4523-8e45-e2d9ed4518ab/resourceGroups/hardikResourceGroup/providers/Microsoft.Storage/storageAccounts/vatsalstorage1
# https://docs.microsoft.com/en-us/rest/api/storagerp/storageaccounts/getproperties

rulepass {
    lower(input.type) == "microsoft.storage/storageaccounts"
    input.properties.supportsHttpsTrafficOnly == true
}

rulepass {
    lower(input.type) == "microsoft.storage/storageaccounts"
    not input.properties.supportsHttpsTrafficOnly
}
