package rule

has_property(parent_object, target_property) { 
	_ = parent_object[target_property]
}

# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/virtual_machine

#
# PR-AZR-TRF-VM-001
#

default vm_aset = null

azure_attribute_absence["vm_aset"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_virtual_machine"
    not resource.properties.availability_set_id
}

azure_issue["vm_aset"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_virtual_machine"
    count(resource.properties.availability_set_id) == 0
}

vm_aset {
    lower(input.resources[_].type) == "azurerm_virtual_machine"
    not azure_attribute_absence["vm_aset"]
    not azure_issue["vm_aset"]
}

vm_aset = false {
    azure_attribute_absence["vm_aset"]
}

vm_aset = false {
    azure_issue["vm_aset"]
}

vm_aset_err = "azurerm_virtual_machine property 'availability_set_id' need to be exist. Its missing from the resource." {
    azure_attribute_absence["vm_aset"]
} else = "Azure Virtual Machine is not assigned to an availability set" {
    azure_issue["vm_aset"]
}

vm_aset_metadata := {
    "Policy Code": "PR-AZR-TRF-VM-001",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Virtual Machine should be assigned to an availability set",
    "Policy Description": "To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.",
    "Resource Type": "azurerm_virtual_machine",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/virtual_machine"
}


# https://github.com/Azure/azure-quickstart-templates/blob/master/quickstarts/microsoft.compute/vm-new-or-existing-conditions/azuredeploy.json
# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/virtual_machine
# PR-AZR-TRF-VM-002
#

default vm_linux_disabled_password_auth = null

azure_attribute_absence["vm_linux_disabled_password_auth"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_virtual_machine"
    os_profile_linux_config := resource.properties.os_profile_linux_config[_]
    not os_profile_linux_config.disable_password_authentication
}

azure_issue["vm_linux_disabled_password_auth"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_virtual_machine"
    os_profile_linux_config := resource.properties.os_profile_linux_config[_]
    os_profile_linux_config.disable_password_authentication != true
}

vm_linux_disabled_password_auth {
    lower(input.resources[_].type) == "azurerm_virtual_machine"
    count(input.resources[_].properties.os_profile_linux_config) > 0
    not azure_attribute_absence["vm_linux_disabled_password_auth"]
    not azure_issue["vm_linux_disabled_password_auth"]
}

vm_linux_disabled_password_auth {
    lower(input.resources[_].type) == "azurerm_virtual_machine"
    count(input.resources[_].properties.os_profile_linux_config) > 0
    azure_attribute_absence["vm_linux_disabled_password_auth"]
    not azure_issue["vm_linux_disabled_password_auth"]
}

vm_linux_disabled_password_auth = false {
    lower(input.resources[_].type) == "azurerm_virtual_machine"
    count(input.resources[_].properties.os_profile_linux_config) > 0
    azure_issue["vm_linux_disabled_password_auth"]
}

vm_linux_disabled_password_auth_err = "Azure Linux Instance currently does not have basic authentication disabled" {
    lower(input.resources[_].type) == "azurerm_virtual_machine"
    count(input.resources[_].properties.os_profile_linux_config) > 0
    azure_issue["vm_linux_disabled_password_auth"]
}

vm_linux_disabled_password_auth_metadata := {
    "Policy Code": "PR-AZR-TRF-VM-002",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Linux Instance should not use basic authentication(Use SSH Key Instead)",
    "Policy Description": "For security purpose, linux vm password authentication should be disabled. Use SSH Key Instead.",
    "Resource Type": "azurerm_virtual_machine",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/virtual_machine"
}


# https://github.com/Azure/azure-quickstart-templates/blob/master/quickstarts/microsoft.compute/vm-new-or-existing-conditions/azuredeploy.json
# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/linux_virtual_machine
# PR-AZR-TRF-VM-004
#

default vm_type_linux_disabled_password_auth = null

azure_attribute_absence["vm_type_linux_disabled_password_auth"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_linux_virtual_machine"
    not resource.properties.disable_password_authentication
}

azure_issue["vm_type_linux_disabled_password_auth"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_linux_virtual_machine"
    resource.properties.disable_password_authentication != true
}

vm_type_linux_disabled_password_auth {
    lower(input.resources[_].type) == "azurerm_linux_virtual_machine"
    not azure_attribute_absence["vm_type_linux_disabled_password_auth"]
    not azure_issue["vm_type_linux_disabled_password_auth"]
}

vm_type_linux_disabled_password_auth {
    lower(input.resources[_].type) == "azurerm_linux_virtual_machine"
    azure_attribute_absence["vm_type_linux_disabled_password_auth"]
    not azure_issue["vm_type_linux_disabled_password_auth"]
}

vm_type_linux_disabled_password_auth = false {
    azure_issue["vm_type_linux_disabled_password_auth"]
}

vm_type_linux_disabled_password_auth_err = "Azure Linux Instance currently does not have basic authentication disabled" {
    azure_issue["vm_type_linux_disabled_password_auth"]
}

vm_type_linux_disabled_password_auth_metadata := {
    "Policy Code": "PR-AZR-TRF-VM-004",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Linux Instance should not use basic authentication(Use SSH Key Instead)",
    "Policy Description": "For security purpose, linux vm password authentication should be disabled. Use SSH Key Instead.",
    "Resource Type": "azurerm_linux_virtual_machine",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/linux_virtual_machine"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/linux_virtual_machine_scale_set
# PR-AZR-TRF-VM-005
#

default vm_type_linux_scale_set_disabled_password_auth = null

azure_attribute_absence["vm_type_linux_scale_set_disabled_password_auth"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_linux_virtual_machine_scale_set"
    not resource.properties.disable_password_authentication
}

azure_issue["vm_type_linux_scale_set_disabled_password_auth"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_linux_virtual_machine_scale_set"
    resource.properties.disable_password_authentication != true
}

vm_type_linux_scale_set_disabled_password_auth {
    lower(input.resources[_].type) == "azurerm_linux_virtual_machine_scale_set"
    not azure_attribute_absence["vm_type_linux_scale_set_disabled_password_auth"]
    not azure_issue["vm_type_linux_scale_set_disabled_password_auth"]
}

vm_type_linux_scale_set_disabled_password_auth {
    lower(input.resources[_].type) == "azurerm_linux_virtual_machine_scale_set"
    azure_attribute_absence["vm_type_linux_scale_set_disabled_password_auth"]
    not azure_issue["vm_type_linux_scale_set_disabled_password_auth"]
}

vm_type_linux_scale_set_disabled_password_auth = false {
    azure_issue["vm_type_linux_scale_set_disabled_password_auth"]
}

vm_type_linux_scale_set_disabled_password_auth_err = "Azure Linux scale set currently does not have basic authentication disabled" {
    azure_issue["vm_type_linux_scale_set_disabled_password_auth"]
}

vm_type_linux_scale_set_disabled_password_auth_metadata := {
    "Policy Code": "PR-AZR-TRF-VM-005",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Linux scale set should not use basic authentication(Use SSH Key Instead)",
    "Policy Description": "For security purpose, linux scale set password authentication should be disabled. Use SSH Key Instead.",
    "Resource Type": "azurerm_linux_virtual_machine_scale_set",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/linux_virtual_machine_scale_set"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/linux_virtual_machine
# PR-AZR-TRF-VM-006
#

default vm_type_linux_disabled_extension_operation = null
# default is true which is wrong in the compute API. default should be false. When there will be a fix in the compute API we need to update the rule accordingly.
# https://github.com/hashicorp/terraform-provider-azurerm/issues/7986
# https://github.com/hashicorp/terraform-provider-azurerm/pull/7996

azure_attribute_absence["vm_type_linux_disabled_extension_operation"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_linux_virtual_machine"
    not has_property(resource.properties, "allow_extension_operations")
}

azure_issue["vm_type_linux_disabled_extension_operation"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_linux_virtual_machine"
    resource.properties.allow_extension_operations == true
}

vm_type_linux_disabled_extension_operation {
    lower(input.resources[_].type) == "azurerm_linux_virtual_machine"
    not azure_attribute_absence["vm_type_linux_disabled_extension_operation"]
    not azure_issue["vm_type_linux_disabled_extension_operation"]
}

vm_type_linux_disabled_extension_operation = false {
    azure_attribute_absence["vm_type_linux_disabled_extension_operation"]
}

vm_type_linux_disabled_extension_operation = false {
    azure_issue["vm_type_linux_disabled_extension_operation"]
}

vm_type_linux_disabled_extension_operation_err = "azurerm_linux_virtual_machine property 'allow_extension_operations' need to be exist. Its missing from the resource." {
    azure_attribute_absence["vm_type_linux_disabled_extension_operation"]
} else = "Azure Linux Instance currently allowing extension operation" {
    azure_issue["vm_type_linux_disabled_extension_operation"]
}

vm_type_linux_disabled_extension_operation_metadata := {
    "Policy Code": "PR-AZR-TRF-VM-006",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Linux Instance should not allow extension operation",
    "Policy Description": "For security purpose, linux vm extension operation should be disabled.",
    "Resource Type": "azurerm_linux_virtual_machine",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/linux_virtual_machine"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/windows_virtual_machine
# PR-AZR-TRF-VM-007
#

default vm_type_windows_disabled_extension_operation = null
# default is true which is wrong in the compute API. default should be false. When there will be a fix in the compute API we need to update the rule accordingly.
# https://github.com/hashicorp/terraform-provider-azurerm/issues/7986
# https://github.com/hashicorp/terraform-provider-azurerm/pull/7996

azure_attribute_absence["vm_type_windows_disabled_extension_operation"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_windows_virtual_machine"
    #not resource.properties.allow_extension_operations
    not has_property(resource.properties, "allow_extension_operations")
}

azure_issue["vm_type_windows_disabled_extension_operation"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_windows_virtual_machine"
    resource.properties.allow_extension_operations == true
}

vm_type_windows_disabled_extension_operation {
    lower(input.resources[_].type) == "azurerm_windows_virtual_machine"
    not azure_attribute_absence["vm_type_windows_disabled_extension_operation"]
    not azure_issue["vm_type_windows_disabled_extension_operation"]
}

vm_type_windows_disabled_extension_operation = false {
    azure_attribute_absence["vm_type_windows_disabled_extension_operation"]
}

vm_type_windows_disabled_extension_operation = false {
    azure_issue["vm_type_windows_disabled_extension_operation"]
}

vm_type_windows_disabled_extension_operation_err = "azurerm_windows_virtual_machine property 'allow_extension_operations' need to be exist. Its missing from the resource." {
    azure_attribute_absence["vm_type_windows_disabled_extension_operation"]
} else = "Azure Windows Instance currently allowing extension operation" {
    azure_issue["vm_type_windows_disabled_extension_operation"]
}

vm_type_windows_disabled_extension_operation_metadata := {
    "Policy Code": "PR-AZR-TRF-VM-007",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Windows Instance should not allow extension operation",
    "Policy Description": "For security purpose, Windows vm extension operation should be disabled.",
    "Resource Type": "azurerm_windows_virtual_machine",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/windows_virtual_machine"
}


#
# PR-AZR-TRF-VM-008
#

default vm_usage_managed_disks = null

azure_attribute_absence["vm_usage_managed_disks"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_virtual_machine"
    not resource.properties.storage_os_disk
}

azure_attribute_absence["vm_usage_managed_disks"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_virtual_machine"
    storage_os_disk := resource.properties.storage_os_disk[_]
    not storage_os_disk.managed_disk_type
}

azure_issue["vm_usage_managed_disks"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_virtual_machine"
    storage_os_disk := resource.properties.storage_os_disk[_]
    count(storage_os_disk.managed_disk_type) == 0
}

vm_usage_managed_disks {
    lower(input.resources[_].type) == "azurerm_virtual_machine"
    not azure_attribute_absence["vm_usage_managed_disks"]
    not azure_issue["vm_usage_managed_disks"]
}

vm_usage_managed_disks = false {
    azure_attribute_absence["vm_usage_managed_disks"]
}

vm_usage_managed_disks = false {
    azure_issue["vm_usage_managed_disks"]
}

vm_usage_managed_disks_err = "azurerm_virtual_machine property 'storage_os_disk.managed_disk_type' need to be exist. Its missing from the resource." {
    azure_attribute_absence["vm_usage_managed_disks"]
} else = "Azure Virtual Machine is not assigned to an availability set" {
    azure_issue["vm_usage_managed_disks"]
}

vm_usage_managed_disks_metadata := {
    "Policy Code": "PR-AZR-TRF-VM-008",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Virtual Machine should utilize managed disks",
    "Policy Description": "This policy identifies Azure Virtual Machines which are not utilising Managed Disks. Using Azure Managed disk over traditional BLOB based VHD's has more advantage features like Managed disks are by default encrypted, reduces cost over storage accounts and more resilient as Microsoft will manage the disk storage and move around if underlying hardware goes faulty. It is recommended to move BLOB based VHD's to Managed Disks.",
    "Resource Type": "azurerm_virtual_machine",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/virtual_machine"
}



#
# PR-AZR-TRF-VM-009
#

default vm_ip_forwarding_disabled = null

azure_attribute_absence["vm_ip_forwarding_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_virtual_machine"
    not resource.properties.network_interface_ids
}

azure_attribute_absence["vm_ip_forwarding_disabled"] {
    count([c | lower(input.resources[_].type) == "azurerm_network_interface"; c := 1]) == 0
}

# azure_attribute_absence["vm_ip_forwarding_disabled"] {
#     resource := input.resources[_]
#     lower(resource.type) == "azurerm_network_interface"
#     not resource.properties.enable_ip_forwarding
# }

azure_issue["vm_ip_forwarding_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_virtual_machine"
    count([c | r := input.resources[_];
              r.type == "azurerm_network_interface";
              #contains(resource.properties.network_interface_ids, r.properties.compiletime_identity); # network_interface_ids is an array, contains will not work here and we can safely ignore this line as the azurerm_network_interface and azurerm_virtual_machine will exist in the same tf file and we can assume those are related
              not r.properties.enable_ip_forwarding;
              c := 1]) == 0
    count([c | r := input.resources[_];
              r.type == "azurerm_network_interface";
              #contains(resource.properties.network_interface_ids, concat(".", [r.type, r.name])); # network_interface_ids is an array, contains will not work here and we can safely ignore this line as the azurerm_network_interface and azurerm_virtual_machine will exist in the same tf file and we can assume those are related
              not r.properties.enable_ip_forwarding;
              c := 1]) == 0
}

vm_ip_forwarding_disabled {
    lower(input.resources[_].type) == "azurerm_virtual_machine"
    not azure_attribute_absence["vm_ip_forwarding_disabled"]
    not azure_issue["vm_ip_forwarding_disabled"]
}

vm_ip_forwarding_disabled = false {
    lower(input.resources[_].type) == "azurerm_virtual_machine"
    azure_issue["vm_ip_forwarding_disabled"]
}

vm_ip_forwarding_disabled {
    lower(input.resources[_].type) == "azurerm_virtual_machine"
    azure_attribute_absence["vm_ip_forwarding_disabled"]
    not azure_issue["vm_ip_forwarding_disabled"]
}

vm_ip_forwarding_disabled_err = "Azure Virtual Machine NIC currently not configured to have IP forwarding disabled" {
    lower(input.resources[_].type) == "azurerm_virtual_machine"
    azure_issue["vm_ip_forwarding_disabled"]
}

vm_ip_forwarding_disabled_metadata := {
    "Policy Code": "PR-AZR-TRF-VM-009",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Virtual Machine NIC should have IP forwarding disabled",
    "Policy Description": "This policy identifies Azure Virtual machine NIC which have IP forwarding enabled. IP forwarding on a virtual machine's NIC allows the machine to receive and forward traffic addressed to other destinations. As a best practice, before you enable IP forwarding in a Virtual Machine NIC, review the configuration with your network security team to ensure that it does not allow an attacker to exploit the set up to route packets through the host and compromise your network.",
    "Resource Type": "azurerm_virtual_machine",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/virtual_machine"
}
