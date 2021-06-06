package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.compute/virtualmachinescalesets/virtualmachines
# https://docs.microsoft.com/en-us/azure/templates/microsoft.compute/virtualmachines

#
# PR-AZR-0065-ARM
#

default vm_aset = null

azure_issue["vm_aset"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.compute/virtualmachinescalesets/virtualmachines"
    not resource.properties.availabilitySet
}

vm_aset {
    lower(input.resources[_].type) == "microsoft.compute/virtualmachinescalesets/virtualmachines"
    not azure_issue["vm_aset"]
}

vm_aset = false {
    azure_issue["vm_aset"]
}

vm_aset_err = "Azure Virtual Machine is not assigned to an availability set" {
    azure_issue["vm_aset"]
}

vm_aset_metadata := {
    "Policy Code": "PR-AZR-0065-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "AWS Cloud formation",
    "Policy Title": "Azure Virtual Machine is not assigned to an availability set",
    "Policy Description": "To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure._x005F_x000D_ _x005F_x000D_ This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.",
    "Resource Type": "microsoft.compute/virtualmachinescalesets/virtualmachines",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.compute/virtualmachinescalesets/virtualmachines"
}
