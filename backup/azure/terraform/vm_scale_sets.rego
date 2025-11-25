package rule

has_property(parent_object, target_property) { 
	_ = parent_object[target_property]
}

array_contains(target_array, element) = true {
  lower(target_array[_]) == lower(element)
} else = false { true }


# 
# PR-AZR-TRF-VMSS-001
#

default vmss_bootdiagonstics_enabled = null

azure_attribute_absence["vmss_bootdiagonstics_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_virtual_machine_scale_set"
    not resource.properties.boot_diagnostics
}

azure_attribute_absence["vmss_bootdiagonstics_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_virtual_machine_scale_set"
    boot_diagnostics := resource.properties.boot_diagnostics[_]
    not has_property(boot_diagnostics, "enabled")
}

azure_issue["vmss_bootdiagonstics_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_virtual_machine_scale_set"
    boot_diagnostics := resource.properties.boot_diagnostics[_]
    boot_diagnostics.enabled != true
}

vmss_bootdiagonstics_enabled {
    lower(input.resources[_].type) == "azurerm_virtual_machine_scale_set"
    not azure_attribute_absence["vmss_bootdiagonstics_enabled"]
    not azure_issue["vmss_bootdiagonstics_enabled"]
}

vmss_bootdiagonstics_enabled = false {
    lower(input.resources[_].type) == "azurerm_virtual_machine_scale_set"
    azure_issue["vmss_bootdiagonstics_enabled"]
}

vmss_bootdiagonstics_enabled = false {
    lower(input.resources[_].type) == "azurerm_virtual_machine_scale_set"
    azure_attribute_absence["vmss_bootdiagonstics_enabled"]
}

vmss_bootdiagonstics_enabled_err = "azurerm_virtual_machine_scale_set resource property boot_diagnostics.enabled is missing in the resource" {
    lower(input.resources[_].type) == "azurerm_virtual_machine_scale_set"
    azure_attribute_absence["vmss_bootdiagonstics_enabled"]
} else = "Azure Virtual Machine scale sets does not configured to have Boot Diagnostics enabled" {
    lower(input.resources[_].type) == "azurerm_virtual_machine_scale_set"
    azure_issue["vmss_bootdiagonstics_enabled"]
}

vmss_bootdiagonstics_enabled_metadata := {
    "Policy Code": "PR-AZR-TRF-VMSS-001",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Virtual Machine scale sets should have Boot Diagnostics enabled",
    "Policy Description": "This policy identifies Azure Virtual Machines scale sets which has Boot Diagnostics setting Disabled. Boot Diagnostics when enabled for virtual machine, captures Screenshot and Console Output during virtual machine startup. This would help in troubleshooting virtual machine when it enters a non-bootable state.",
    "Resource Type": "azurerm_virtual_machine_scale_set",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/virtual_machine_scale_set"
}


# 
# PR-AZR-TRF-VMSS-002
#

default vmss_usage_managed_disks = null

azure_attribute_absence["vmss_usage_managed_disks"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_virtual_machine_scale_set"
    not resource.properties.storage_profile_os_disk
}

azure_attribute_absence["vmss_usage_managed_disks"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_virtual_machine_scale_set"
    storage_profile_os_disk := resource.properties.storage_profile_os_disk[_]
    not storage_profile_os_disk.managed_disk_type
}

azure_issue["vmss_usage_managed_disks"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_virtual_machine_scale_set"
    storage_profile_os_disk := resource.properties.storage_profile_os_disk[_]
    count(storage_profile_os_disk.managed_disk_type) == 0
}

vmss_usage_managed_disks {
    lower(input.resources[_].type) == "azurerm_virtual_machine_scale_set"
    not azure_attribute_absence["vmss_usage_managed_disks"]
    not azure_issue["vmss_usage_managed_disks"]
}

vmss_usage_managed_disks = false {
    azure_attribute_absence["vmss_usage_managed_disks"]
}

vmss_usage_managed_disks = false {
    azure_issue["vmss_usage_managed_disks"]
}

vmss_usage_managed_disks_err = "azurerm_virtual_machine_scale_set property 'storage_profile_os_disk.managed_disk_type' need to be exist. Its missing from the resource." {
    azure_attribute_absence["vmss_usage_managed_disks"]
} else = "Azure Virtual Machine scale sets currently not utilizing managed disks" {
    azure_issue["vmss_usage_managed_disks"]
}

vmss_usage_managed_disks_metadata := {
    "Policy Code": "PR-AZR-TRF-VMSS-002",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Virtual Machine scale sets should utilize managed disks",
    "Policy Description": "This policy identifies Azure Virtual machine scale sets which are not utilising Managed Disks. Using Azure Managed disk over traditional BLOB storage based VHD's has more advantage features like Managed disks are by default encrypted, reduces cost over storage accounts and more resilient as Microsoft will manage the disk storage and move around if underlying hardware goes faulty. It is recommended to move BLOB based VHD's to Managed Disks.",
    "Resource Type": "azurerm_virtual_machine_scale_set",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/virtual_machine_scale_set"
}