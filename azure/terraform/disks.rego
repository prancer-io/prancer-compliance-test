package rule

# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/managed_disk

#
# PR-AZR-0068-TRF
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
    "Policy Code": "PR-AZR-0068-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure disk should have Azure Disk Encryption (ADE) enabled",
    "Policy Description": "To meet your organizational security or compliance requirement, Azure provides disk encryption at rest using Azure Storage Service Encryption (SSE) and Azure Disk Encryption (ADE). Starting February 2017, SSE is enabled by default for all managed disks. ADE is integrated with Azure Key Vault to help you control, manage, and audit the disk encryption keys and secrets._x005F_x000D_ _x005F_x000D_ This policy detects Virtual Machine (VM) OS disks that are not encrypted at rest using ADE. As a best practice, enable ADE for provide volume encryption for the OS disk. For more information, see https://docs.microsoft.com/en-us/azure/security/azure-security-disk-encryption-overview.",
    "Resource Type": "azurerm_managed_disk",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/managed_disk"
}
