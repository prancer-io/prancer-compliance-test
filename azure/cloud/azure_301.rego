package rule

default rulepass = false

# Azure disk for VM operating system is not encrypted at rest using ADE
# If availability set is enabled test will pass

# https://resources.azure.com/subscriptions/db3667b7-cef9-4523-8e45-e2d9ed4518ab/resourceGroups/hardikResourceGroup/providers/Microsoft.Storage/storageAccounts/vatsalstorage1
# https://docs.microsoft.com/en-us/rest/api/storagerp/storageaccounts/getproperties

rulepass = true {                                      
   count(supportsHttpsTrafficOnly) == 2
}

# "$.['properties.supportsHttpsTrafficOnly'] exists or 
# $.['properties.supportsHttpsTrafficOnly'] is true"

supportsHttpsTrafficOnly["supportsHttpsTrafficOnly_exist"] {
   input.properties.supportsHttpsTrafficOnly 
}

supportsHttpsTrafficOnly["supportsHttpsTrafficOnly_false"] {   
   input.properties.supportsHttpsTrafficOnly = true
}