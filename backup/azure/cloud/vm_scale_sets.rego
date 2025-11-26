package rule

has_property(parent_object, target_property) { 
	_ = parent_object[target_property]
}

array_contains(target_array, element) = true {
  lower(target_array[_]) == lower(element)
} else = false { true }


# 
# PR-AZR-CLD-VMSS-001
#

default vmss_bootdiagonstics_enabled = null

azure_attribute_absence["vmss_bootdiagonstics_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.compute/virtualmachinescalesets"
    not resource.properties.virtualMachineProfile.diagnosticsProfile.bootDiagnostics.enabled
}

azure_issue["vmss_bootdiagonstics_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.compute/virtualmachinescalesets"
    resource.properties.virtualMachineProfile.diagnosticsProfile.bootDiagnostics.enabled != true
}

vmss_bootdiagonstics_enabled {
    lower(input.resources[_].type) == "microsoft.compute/virtualmachinescalesets"
    not azure_attribute_absence["vmss_bootdiagonstics_enabled"]
    not azure_issue["vmss_bootdiagonstics_enabled"]
}

vmss_bootdiagonstics_enabled = false {
    lower(input.resources[_].type) == "microsoft.compute/virtualmachinescalesets"
    azure_issue["vmss_bootdiagonstics_enabled"]
}

vmss_bootdiagonstics_enabled = false {
    lower(input.resources[_].type) == "microsoft.compute/virtualmachinescalesets"
    azure_attribute_absence["vmss_bootdiagonstics_enabled"]
}

vmss_bootdiagonstics_enabled_err = "microsoft.compute/virtualmachinescalesets resource property virtualMachineProfile.diagnosticsProfile.bootDiagnostics.enabled is missing in the resource" {
    lower(input.resources[_].type) == "microsoft.compute/virtualmachinescalesets"
    azure_attribute_absence["vmss_bootdiagonstics_enabled"]
} else = "Azure Virtual Machine scale sets does not configured to have Boot Diagnostics enabled" {
    lower(input.resources[_].type) == "microsoft.compute/virtualmachinescalesets"
    azure_issue["vmss_bootdiagonstics_enabled"]
}

vmss_bootdiagonstics_enabled_metadata := {
    "Policy Code": "PR-AZR-CLD-VMSS-001",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure Virtual Machine scale sets should have Boot Diagnostics enabled",
    "Policy Description": "This policy identifies Azure Virtual Machines scale sets which has Boot Diagnostics setting Disabled. Boot Diagnostics when enabled for virtual machine, captures Screenshot and Console Output during virtual machine startup. This would help in troubleshooting virtual machine when it enters a non-bootable state.",
    "Resource Type": "microsoft.compute/virtualmachinescalesets",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/Microsoft.Compute/virtualmachinescalesets?pivots=deployment-language-arm-template"
}


# 
# PR-AZR-CLD-VMSS-002
#

default vmss_usage_managed_disks = null

azure_attribute_absence["vmss_usage_managed_disks"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.compute/virtualmachinescalesets"
    not resource.properties.virtualMachineProfile.storageProfile.osDisk.managedDisk
}

vmss_usage_managed_disks {
    lower(input.resources[_].type) == "microsoft.compute/virtualmachinescalesets"
    not azure_attribute_absence["vmss_usage_managed_disks"]
}

vmss_usage_managed_disks = false {
    azure_attribute_absence["vmss_usage_managed_disks"]
}

vmss_usage_managed_disks_err = "Azure Virtual Machine scale sets currently not utilizing managed disks" {
   azure_attribute_absence["vmss_usage_managed_disks"]
}

vmss_usage_managed_disks_metadata := {
    "Policy Code": "PR-AZR-CLD-VMSS-002",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure Virtual Machine scale sets should utilize managed disks",
    "Policy Description": "This policy identifies Azure Virtual machine scale sets which are not utilising Managed Disks. Using Azure Managed disk over traditional BLOB storage based VHD's has more advantage features like Managed disks are by default encrypted, reduces cost over storage accounts and more resilient as Microsoft will manage the disk storage and move around if underlying hardware goes faulty. It is recommended to move BLOB based VHD's to Managed Disks.",
    "Resource Type": "microsoft.compute/virtualmachinescalesets",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/Microsoft.Compute/virtualmachinescalesets?pivots=deployment-language-arm-template"
}