package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts

#
# PR-AZR-0092-ARM
#

default storage_secure = null

azure_attribute_absence["storage_secure"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    resource.apiVersion < "2019-04-01"
    not resource.properties.supportsHttpsTrafficOnly
}

azure_issue["storage_secure"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    resource.properties.supportsHttpsTrafficOnly == false
}

storage_secure {
    lower(input.resources[_].type) == "microsoft.storage/storageaccounts"
    not azure_issue["storage_secure"]
    not azure_attribute_absence["storage_secure"]
}

storage_secure = false {
    azure_issue["storage_secure"]
}

storage_secure = false {
    azure_attribute_absence["storage_secure"]
}

storage_secure_err = "Storage Accounts without Secure transfer enabled" {
    azure_issue["storage_secure"]
}

storage_secure_miss_err = "Storage Account attribute supportsHttpsTrafficOnly missing in the resource" {
    azure_attribute_absence["storage_secure"]
}

storage_secure_metadata := {
    "Policy Code": "PR-AZR-0092-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Storage Accounts without Secure transfer enabled",
    "Policy Description": "The secure transfer option enhances the security of your storage account by only allowing requests to the storage account by a secure connection. For example, when calling REST APIs to access your storage accounts, you must connect using HTTPs. Any requests using HTTP will be rejected when 'secure transfer required' is enabled. When you are using the Azure files service, connection without encryption will fail, including scenarios using SMB 2.1, SMB 3.0 without encryption, and some flavors of the Linux SMB client. Because Azure storage doesnâ€™t support HTTPs for custom domain names, this option is not applied when using a custom domain name.",
    "Resource Type": "microsoft.storage/storageaccounts",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts"
}

#
# PR-AZR-0093-ARM
#

default storage_acl = null

azure_attribute_absence["storage_acl"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not resource.properties.networkAcls.defaultAction
}

azure_issue["storage_acl"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    lower(resource.properties.networkAcls.defaultAction) != "deny"
}

storage_acl {
    lower(input.resources[_].type) == "microsoft.storage/storageaccounts"
    not azure_issue["storage_acl"]
    not azure_attribute_absence["storage_acl"]
}

storage_acl = false {
    azure_issue["storage_acl"]
}

storage_acl = false {
    azure_attribute_absence["storage_acl"]
}

storage_acl_err = "Storage Accounts without their firewalls enabled" {
    azure_issue["storage_acl"]
}

storage_acl_miss_err = "Storage Account attribute networkAcls.defaultAction missing in the resource" {
    azure_attribute_absence["storage_acl"]
}

storage_acl_metadata := {
    "Policy Code": "PR-AZR-0093-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Storage Accounts without their firewalls enabled (TJX)",
    "Policy Description": "Turning on firewall rules for your storage account blocks incoming requests for data by default, unless the requests come from a service that is operating within an Azure Virtual Network (VNet). Requests that are blocked include those from other Azure services, from the Azure portal, from logging and metrics services, and so on._x005F_x000D_ _x005F_x000D_ You can grant access to Azure services that operate from within a VNet by allowing the subnet of the service instance. Enable a limited number of scenarios through the Exceptions mechanism described in the following section. To access the Azure portal, you would need to be on a machine within the trusted boundary (either IP or VNet) that you set up.",
    "Resource Type": "microsoft.storage/storageaccounts",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts"
}

#
# Advanced Threat Protection should be enabled for all the storage accounts (unknown)
#

default storage_threat_protection = null

azure_issue["storage_threat_protection"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    nested := resource.resources[_]
    lower(nested.type) == "providers/advancedthreatprotectionsettings"
    nested.properties.isEnabled != true
}

azure_issue["storage_threat_protection"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    nested := input.resources[_]
    lower(nested.type) == "providers/advancedthreatprotectionsettings"
    nested.properties.isEnabled != true
    nested_type := "providers/advancedthreatprotectionsettings"
    count([ c | lower(resource.resources[_].type) == nested_type; c = 1]) == 0
}

storage_threat_protection {
    lower(input.resources[_].type) == "microsoft.storage/storageaccounts"
    not azure_issue["storage_threat_protection"]
}

storage_threat_protection = false {
    azure_issue["storage_threat_protection"]
}

storage_threat_protection_err = "Advanced Threat Protection not enabled for all the storage accounts" {
    azure_issue["storage_threat_protection"]
}

storage_threat_protection_metadata := {
    "Policy Code": "",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Advanced Threat Protection not enabled for all the storage accounts",
    "Policy Description": "Advanced Threat Protection should be enabled for all the storage accounts",
    "Resource Type": "microsoft.storage/storageaccounts",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts"
}



# PR-AZR-0112-ARM

default blobService = null

azure_attribute_absence["blobService"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not resource.properties.encryption.services.blob
}

azure_issue["blobService"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    resource.properties.encryption.services.blob.enabled != true
}

blobService {
    lower(input.resources[_].type) == "microsoft.storage/storageaccounts"
    not azure_issue["blobService"]
    not azure_attribute_absence["blobService"]
}

blobService = false {
    azure_issue["blobService"]
}

blobService = false {
    azure_attribute_absence["blobService"]
}

blobService_err = "Ensure that 'Storage service encryption' is enabled for the Blob Service" {
    azure_issue["blobService"]
}

blobService_miss_err = "Ensure that 'Storage service encryption' is enabled for the Blob Service" {
    azure_attribute_absence["blobService"]
}

blobService_metadata := {
    "Policy Code": "PR-AZR-0112-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure that 'Storage service encryption' is enabled for the Blob Service",
    "Policy Description": "Enable data encryption at rest for blobs. Storage service encryption protects your data at rest. Azure Storage encrypts data when it's written, and automatically decrypts it when it is accessed.",
    "Resource Type": "microsoft.storage/storageaccounts",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts"
}


# PR-AZR-0113-ARM

default fileService = null

azure_attribute_absence["fileService"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not resource.properties.encryption.services.file
}

azure_issue["fileService"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    resource.properties.encryption.services.file.enabled != true
}

fileService {
    lower(input.resources[_].type) == "microsoft.storage/storageaccounts"
    not azure_issue["fileService"]
    not azure_attribute_absence["fileService"]
}

fileService = false {
    azure_issue["fileService"]
}

fileService = false {
    azure_attribute_absence["fileService"]
}

fileService_err = "Ensure that 'Storage service encryption' is enabled for the File Service" {
    azure_issue["fileService"]
}

fileService_miss_err = "Ensure that 'Storage service encryption' is enabled for the File Service" {
    azure_attribute_absence["fileService"]
}

fileService_metadata := {
    "Policy Code": "PR-AZR-0113-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure that 'Storage service encryption' is enabled for the File Service",
    "Policy Description": "Azure Storage encryption protects your data and to help you to meet your organizational security and compliance commitments. Data in Azure Storage is encrypted and decrypted transparently using 256-bit AES encryption, one of the strongest block ciphers available, and is FIPS 140-2 compliant. Azure Storage encryption is similar to BitLocker encryption on Windows.",
    "Resource Type": "microsoft.storage/storageaccounts",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts"
}




# PR-AZR-0114-ARM

default keySource = null

azure_issue["fileService"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    lower(resource.properties.encryption.keySource) != "microsoft.keyvault"
}

keySource {
    lower(input.resources[_].type) == "microsoft.storage/storageaccounts"
    not azure_issue["keySource"]
}

keySource = false {
    azure_issue["keySource"]
}


keySource_err = "Ensure storage for critical data are encrypted with Customer Managed Key" {
    azure_issue["keySource"]
}


keySource_metadata := {
    "Policy Code": "PR-AZR-0114-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure storage for critical data are encrypted with Customer Managed Key",
    "Policy Description": "By default, data in the storage account is encrypted using Microsoft Managed Keys at rest. All Azure Storage resources are encrypted, including blobs, disks, files, queues, and tables. All object metadata is also encrypted. However, if you want to control and manage this encryption key yourself, you can specify a customer-managed key, that key is used to protect and control access to the key that encrypts your data. You can also choose to automatically update the key version used for Azure Storage encryption whenever a new version is available in the associated Key Vault.",
    "Resource Type": "microsoft.storage/storageaccounts",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts"
}



# PR-AZR-0122-ARM

default region = null

azure_issue["region"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    lower(resource.location) != "northeurope"
    lower(resource.location) != "westeurope"
}

region {
    lower(input.resources[_].type) == "microsoft.storage/storageaccounts"
    not azure_issue["region"]
}

region = false {
    azure_issue["region"]
}

region_err = "Storage Accounts outside Europe" {
    azure_issue["region"]
}

region_metadata := {
    "Policy Code": "PR-AZR-0122-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Storage Accounts outside Europe",
    "Policy Description": "Identify Storage Accounts outside of the following regions: northeurope, westeurope",
    "Resource Type": "microsoft.storage/storageaccounts",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts"
}