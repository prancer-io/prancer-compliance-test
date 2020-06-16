package rule

default rulepass = false

# Azure Virtual Machine is not assigned to an availability set
# If availability set is enabled test will pass

# https://docs.microsoft.com/en-us/rest/api/compute/virtualmachines/get
# https://resources.azure.com/subscriptions/db3667b7-cef9-4523-8e45-e2d9ed4518ab/resourceGroups/hardikResourceGroup/providers/Microsoft.Compute/virtualMachines/hardikVM

rulepass {
   input.properties.availabilitySet
}
