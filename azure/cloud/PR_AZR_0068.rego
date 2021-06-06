#
# PR-AZR-0068
#

package rule
default rulepass = false

# Azure disk for VM operating system is not encrypted at rest using ADE
# If disk for VM operating system is encrypted test will pass

# https://docs.microsoft.com/en-us/rest/api/compute/disks/get
# https://resources.azure.com/subscriptions/db3667b7-cef9-4523-8e45-e2d9ed4518ab/resourceGroups/hardikResourceGroup/providers/Microsoft.Compute/disks

rulepass {
    lower(input.type) == "microsoft.compute/disks"
    count(disks) == 1
}

metadata := {
    "Policy Code": "PR-AZR-0068",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "Cloud",
    "Policy Title": "Azure disk for VM operating system is not encrypted at rest using ADE",
    "Policy Description": "To meet your organizational security or compliance requirement, Azure provides disk encryption at rest using Azure Storage Service Encryption (SSE) and Azure Disk Encryption (ADE). Starting February 2017, SSE is enabled by default for all managed disks. ADE is integrated with Azure Key Vault to help you control, manage, and audit the disk encryption keys and secrets._x005F_x000D_ _x005F_x000D_ This policy detects Virtual Machine (VM) OS disks that are not encrypted at rest using ADE. As a best practice, enable ADE for provide volume encryption for the OS disk. For more information, see https://docs.microsoft.com/en-us/azure/security/azure-security-disk-encryption-overview.",
    "Resource Type": "microsoft.compute/disks",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/rest/api/compute/disks/get"
}

# 'osType exists and
# (encryptionSettings is exist or
# encryptionSettings.enabled == true)'

disks["osType exists"] {
    input.properties.osType
    input.properties.encryptionSettingsCollection.encryptionSettings
    input.properties.encryptionSettingsCollection.enabled == true
}

disks["osType Not exists"] {
    not input.properties.osType
}
