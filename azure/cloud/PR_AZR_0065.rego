#
# PR-AZR-0065
#

package rule

default rulepass = false

# Azure Virtual Machine is not assigned to an availability set
# If availability set is enabled test will pass

# https://docs.microsoft.com/en-us/rest/api/compute/virtualmachines/get
# https://resources.azure.com/subscriptions/db3667b7-cef9-4523-8e45-e2d9ed4518ab/resourceGroups/hardikResourceGroup/providers/Microsoft.Compute/virtualMachines/hardikVM

rulepass {
    lower(input.type) == "microsoft.compute/virtualmachines"
    input.properties.availabilitySet
}

metadata := {
    "Policy Code": "PR-AZR-0065",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "Cloud",
    "Policy Title": "Azure Virtual Machine is not assigned to an availability set",
    "Policy Description": "To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure._x005F_x000D_ _x005F_x000D_ This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.",
    "Compliance": [],
    "Resource Type": "microsoft.compute/virtualmachines",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/rest/api/compute/virtualmachines/get"
}
