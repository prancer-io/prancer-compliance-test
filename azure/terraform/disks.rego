package rule

# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/managed_disk

#
# PR-AZR-TRF-DSK-001
#

default disk_encrypt = null

azure_attribute_absence["disk_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_managed_disk"
    not resource.properties.encryption_settings
}

azure_attribute_absence["disk_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_managed_disk"
    encryption_settings := resource.properties.encryption_settings[_]
    not encryption_settings.enabled
}

azure_issue["disk_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_managed_disk"
    encryption_settings := resource.properties.encryption_settings[_]
    encryption_settings.enabled != true
}

disk_encrypt = false {
    azure_attribute_absence["disk_encrypt"]
}

disk_encrypt {
    lower(input.resources[_].type) == "azurerm_managed_disk"
    not azure_attribute_absence["disk_encrypt"]
    not azure_issue["disk_encrypt"]
}

disk_encrypt = false {
    azure_issue["disk_encrypt"]
}

disk_encrypt_err = "azurerm_managed_disk property 'encryption_settings.enabled' is missing from the resource. Please set the value to 'true' after property addition." {
    azure_attribute_absence["disk_encrypt"]
} else = "Azure disk currently does not have Azure Disk Encryption (ADE) enabled" {
    azure_issue["disk_encrypt"]
}

disk_encrypt_metadata := {
    "Policy Code": "PR-AZR-TRF-DSK-001",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure disk should have Azure Disk Encryption (ADE) enabled",
    "Policy Description": "To meet your organizational security or compliance requirement, Azure provides disk encryption at rest using Azure Storage Service Encryption (SSE) and Azure Disk Encryption (ADE). Starting February 2017, SSE is enabled by default for all managed disks. ADE is integrated with Azure Key Vault to help you control, manage, and audit the disk encryption keys and secrets.<br><br>This policy detects Virtual Machine (VM) OS disks that are not encrypted at rest using ADE. As a best practice, enable ADE for provide volume encryption for the OS disk. For more information, see https://docs.microsoft.com/en-us/azure/security/azure-security-disk-encryption-overview.",
    "Resource Type": "azurerm_managed_disk",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/managed_disk"
}

# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/managed_disk

#
# PR-AZR-TRF-DSK-002
#

default disk_encrypt_cmk = null

azure_attribute_absence["disk_encrypt_cmk"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_managed_disk"
    not resource.properties.disk_encryption_set_id
}

azure_issue["disk_encrypt_cmk"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_managed_disk"
    disk_encryption_set_id_found = resource.properties.disk_encryption_set_id
    count([c | r := input.resources[_];
              r.type == "azurerm_disk_encryption_set";
              contains(disk_encryption_set_id_found, r.properties.compiletime_identity);
              c := 1]) == 0
}

disk_encrypt_cmk = false {
    azure_attribute_absence["disk_encrypt_cmk"]
}

disk_encrypt_cmk {
    lower(input.resources[_].type) == "azurerm_managed_disk"
    not azure_attribute_absence["disk_encrypt_cmk"]
    not azure_issue["disk_encrypt_cmk"]
}

disk_encrypt_cmk = false {
    azure_issue["disk_encrypt_cmk"]
}

disk_encrypt_cmk_err = "azurerm_managed_disk property 'disk_encryption_set_id' is missing from the resource. Please set id of target 'azurerm_disk_encryption_set' as value after property addition." {
    azure_attribute_absence["disk_encrypt_cmk"]
} else = "Azure disk currently does not have  CMK disk encryption enabled" {
    azure_issue["disk_encrypt_cmk"]
}

disk_encrypt_cmk_metadata := {
    "Policy Code": "PR-AZR-TRF-DSK-002",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure disk should have CMK disk encryption enabled",
    "Policy Description": "SSE with CMK is integrated with Azure Key Vault, which provides highly available and scalable secure storage for your keys backed by Hardware Security Modules. You can either bring your own keys (BYOK) to your Key Vault or generate new keys in the Key Vault. For more information, see https://azure.microsoft.com/en-in/blog/announcing-serverside-encryption-with-customermanaged-keys-for-azure-managed-disks/",
    "Resource Type": "azurerm_managed_disk",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/managed_disk"
}
