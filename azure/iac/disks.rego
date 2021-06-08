package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.compute/disks

#
# PR-AZR-0068-ARM
#

default disk_encrypt = null

azure_attribute_absence["disk_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.compute/disks"
    resource.properties.osType
    not resource.properties.encryptionSettingsCollection.encryptionSettings
    resource.properties.encryptionSettingsCollection.enabled == true
}

azure_issue["disk_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.compute/disks"
    resource.properties.osType
    resource.properties.encryptionSettingsCollection.enabled != true
}

azure_issue["disk_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.compute/disks"
    resource.properties.osType
    not resource.properties.encryptionSettingsCollection.enabled
}

disk_encrypt {
    lower(input.resources[_].type) == "microsoft.compute/disks"
    not azure_issue["disk_encrypt"]
    not azure_attribute_absence["disk_encrypt"]
}

disk_encrypt = false {
    azure_issue["disk_encrypt"]
}

disk_encrypt = false {
    azure_attribute_absence["disk_encrypt"]
}

disk_encrypt_err = "Azure disk for VM operating system is not encrypted at rest using ADE" {
    azure_issue["disk_encrypt"]
}

disk_encrypt_miss_err = "Disk attribute encryptionSettings missing in the resource" {
    azure_attribute_absence["disk_encrypt"]
}

disk_encrypt_metadata := {
    "Policy Code": "PR-AZR-0068-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure disk for VM operating system is not encrypted at rest using ADE",
    "Policy Description": "To meet your organizational security or compliance requirement, Azure provides disk encryption at rest using Azure Storage Service Encryption (SSE) and Azure Disk Encryption (ADE). Starting February 2017, SSE is enabled by default for all managed disks. ADE is integrated with Azure Key Vault to help you control, manage, and audit the disk encryption keys and secrets._x005F_x000D_ _x005F_x000D_ This policy detects Virtual Machine (VM) OS disks that are not encrypted at rest using ADE. As a best practice, enable ADE for provide volume encryption for the OS disk. For more information, see https://docs.microsoft.com/en-us/azure/security/azure-security-disk-encryption-overview.",
    "Compliance": [],
    "Resource Type": "microsoft.compute/disks",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.compute/disks"
}
