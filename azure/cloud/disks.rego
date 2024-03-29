package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.compute/disks

#
# PR-AZR-CLD-DSK-001
#

default disk_encrypt = null

#azure_attribute_absence["disk_encryption_2"] {
#    resource := input.resources[_]
#    lower(resource.type) == "microsoft.compute/disks"
#    resource.properties.osType
#    not resource.properties.encryptionSettingsCollection.encryptionSettings
#    resource.properties.encryptionSettingsCollection.enabled == true
#}

azure_attribute_absence["disk_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.compute/disks"
    #resource.properties.osType
    not resource.properties.encryptionSettingsCollection.enabled
}


azure_issue["disk_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.compute/disks"
    #resource.properties.osType
    resource.properties.encryptionSettingsCollection.enabled != true
}


disk_encrypt = false {
    azure_attribute_absence["disk_encrypt"]
}

disk_encrypt {
    lower(input.resources[_].type) == "microsoft.compute/disks"
    not azure_attribute_absence["disk_encrypt"]
    not azure_issue["disk_encrypt"]
}

disk_encrypt = false {
    azure_issue["disk_encrypt"]
}

disk_encrypt_err = "microsoft.compute/disks resoruce property encryptionSettingsCollection.enabled is missing" {
    azure_attribute_absence["disk_encrypt"]
} else = "Azure disk currently does not have Azure Disk Encryption (ADE) enabled" {
    azure_issue["disk_encrypt"]
}

disk_encrypt_metadata := {
    "Policy Code": "PR-AZR-CLD-DSK-001",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure disk should have Azure Disk Encryption (ADE) enabled",
    "Policy Description": "To meet your organizational security or compliance requirement, Azure provides disk encryption at rest using Azure Storage Service Encryption (SSE) and Azure Disk Encryption (ADE). Starting February 2017, SSE is enabled by default for all managed disks. ADE is integrated with Azure Key Vault to help you control, manage, and audit the disk encryption keys and secrets.<br><br>This policy detects Virtual Machine (VM) OS disks that are not encrypted at rest using ADE. As a best practice, enable ADE for provide volume encryption for the OS disk. For more information, see https://docs.microsoft.com/en-us/azure/security/azure-security-disk-encryption-overview.",
    "Resource Type": "microsoft.compute/disks",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.compute/disks"
}

# PR-AZR-CLD-DSK-002
#

default disk_encryption_2 = null


azure_attribute_absence["disk_encryption_2"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.compute/disks"
    not resource.properties.encryption.diskEncryptionSetId
}

azure_attribute_absence["disk_encryption_2"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.compute/disks"
    not resource.properties.encryption.type
}


azure_issue["disk_encryption_2"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.compute/disks"
    count(resource.properties.encryption.diskEncryptionSetId) == 0
}


azure_issue["disk_encryption_2"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.compute/disks"
    lower(resource.properties.encryption.type) == "encryptionatrestwithplatformkey"
}


disk_encryption_2 = false {
    azure_attribute_absence["disk_encryption_2"]
}

disk_encryption_2 {
    lower(input.resources[_].type) == "microsoft.compute/disks"
    not azure_attribute_absence["disk_encryption_2"]
    not azure_issue["disk_encryption_2"]
}

disk_encryption_2 = false {
    azure_issue["disk_encryption_2"]
}


disk_encryption_2_err = "Azure disk currently does not have Azure Disk Encryption (ADE) with EncryptionAtRestWithCustomerKey" {
    azure_issue["disk_encryption_2"]
} else = "microsoft.compute/disks resoruce property encryption.diskEncryptionSetId or encryption.type is missing" {
    azure_attribute_absence["disk_encryption_2"]
}

disk_encryption_2_metadata := {
    "Policy Code": "PR-AZR-CLD-DSK-002",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Enable server-side encryption with customer-managed keys for managed disks",
    "Policy Description": "Azure Disk Storage allows you to manage your own keys when using server-side encryption (SSE) for managed disks, if you choose",
    "Resource Type": "microsoft.compute/disks",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.compute/disks"
}
