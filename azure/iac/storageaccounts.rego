package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts

#
# PR-AZR-0092-ARM
#

default storage_secure = null

#in latest API from 2019-04-01, supportsHttpsTrafficOnly is true by default if not exist
azure_attribute_absence_new["storage_secure"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    resource.apiVersion >= "2019-04-01"
    not resource.properties.supportsHttpsTrafficOnly
}

#in older API before 2019-04-01, supportsHttpsTrafficOnly is false by default if not exist
azure_attribute_absence_old["storage_secure"] {
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
    not azure_attribute_absence_old["storage_secure"]
    not azure_issue["storage_secure"]
}

storage_secure {
    azure_attribute_absence_new["storage_secure"]
    not azure_issue["storage_secure"]
}

storage_secure = false {
    azure_issue["storage_secure"]
}

storage_secure = false {
    azure_attribute_absence_old["storage_secure"]
}


storage_secure_err = "Storage Accounts https based secure transfer is not enabled" {
    azure_issue["storage_secure"]
}


storage_secure_metadata := {
    "Policy Code": "PR-AZR-0092-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Storage Accounts https based secure transfer should be enabled",
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
    not azure_attribute_absence["storage_acl"]
    not azure_issue["storage_acl"]
}

storage_acl = false {
    azure_issue["storage_acl"]
}

storage_acl = false {
    azure_attribute_absence["storage_acl"]
}

storage_acl_err = "Storage Accounts firewall rule is currently not enabled" {
    azure_issue["storage_acl"]
}

storage_acl_miss_err = "Storage Account attribute networkAcls.defaultAction is missing from the resource" {
    azure_attribute_absence["storage_acl"]
}

storage_acl_metadata := {
    "Policy Code": "PR-AZR-0093-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Storage Accounts should have firewall rules enabled",
    "Policy Description": "Turning on firewall rules for your storage account blocks incoming requests for data by default, unless the requests come from a service that is operating within an Azure Virtual Network (VNet). Requests that are blocked include those from other Azure services, from the Azure portal, from logging and metrics services, and so on.<br><br>You can grant access to Azure services that operate from within a VNet by allowing the subnet of the service instance. Enable a limited number of scenarios through the Exceptions mechanism described in the following section. To access the Azure portal, you would need to be on a machine within the trusted boundary (either IP or VNet) that you set up.",
    "Resource Type": "microsoft.storage/storageaccounts",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts"
}

# https://docs.microsoft.com/en-us/azure/templates/microsoft.security/advancedthreatprotectionsettings?tabs=json
# Advanced Threat Protection should be enabled for storage account
# PR-AZR-0094-ARM

default storage_threat_protection = null

azure_issue["storage_threat_protection"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    #nested := input.resources[_]
    #lower(nested.type) == "providers/advancedthreatprotectionsettings"
    #nested.properties.isEnabled != true
    nested_type := "providers/advancedthreatprotectionsettings"
    count([ c | lower(resource.resources[_].type) == nested_type; c = 1]) == 0
}

azure_issue["storage_threat_protection"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    nested := resource.resources[_]
    lower(nested.type) == "providers/advancedthreatprotectionsettings"
    not nested.properties.isEnabled
}

azure_issue["storage_threat_protection"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    nested := resource.resources[_]
    lower(nested.type) == "providers/advancedthreatprotectionsettings"
    nested.properties.isEnabled != true
}

storage_threat_protection {
    lower(input.resources[_].type) == "microsoft.storage/storageaccounts"
    not azure_issue["storage_threat_protection"]
}

storage_threat_protection = false {
    azure_issue["storage_threat_protection"]
}

storage_threat_protection_err = "Advanced Threat Protection is currently not enabled for storage account" {
    azure_issue["storage_threat_protection"]
}

storage_threat_protection_metadata := {
    "Policy Code": "PR-AZR-0094-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Advanced Threat Protection should be enabled for storage account",
    "Policy Description": "Advanced Threat Protection should be enabled for all the storage accounts",
    "Resource Type": "microsoft.storage/storageaccounts",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts"
}


# https://azure.microsoft.com/en-us/blog/announcing-default-encryption-for-azure-blobs-files-table-and-queue-storage/
# This feature is enabled by default thats why Terraform does not have any property for that
# PR-AZR-0112-ARM

default blobService = null

azure_attribute_absence["blobService"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not resource.properties.encryption.services.blob.enabled
}

azure_issue["blobService"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    resource.properties.encryption.services.blob.enabled != true
}

blobService {
    lower(input.resources[_].type) == "microsoft.storage/storageaccounts"
    not azure_attribute_absence["blobService"]
    not azure_issue["blobService"]
}

blobService  {
    azure_attribute_absence["blobService"]
    not azure_issue["blobService"]
}

blobService = false {
    azure_issue["blobService"]
}


blobService_err = "Ensure that 'Storage service encryption' is enabled for the Blob Service" {
    azure_issue["blobService"]
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

# https://azure.microsoft.com/en-us/blog/announcing-default-encryption-for-azure-blobs-files-table-and-queue-storage/
# This feature is enabled by default thats why Terraform does not have any property for that
# PR-AZR-0113-ARM

default fileService = null

azure_attribute_absence["fileService"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not resource.properties.encryption.services.file.enabled
}

azure_issue["fileService"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    resource.properties.encryption.services.file.enabled != true
}

fileService {
    lower(input.resources[_].type) == "microsoft.storage/storageaccounts"
    not azure_attribute_absence["fileService"]
    not azure_issue["fileService"]
}

fileService {
    azure_attribute_absence["fileService"]
    not azure_issue["fileService"]
}

fileService = false {
    azure_issue["fileService"]
}


fileService_err = "Ensure that 'Storage service encryption' is enabled for the File Service" {
    azure_issue["fileService"]
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



# https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts
# PR-AZR-0114-ARM

default keySource = null

azure_attribute_absence["keySource"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not resource.properties.encryption.keySource
}

azure_issue["keySource"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    lower(resource.properties.encryption.keySource) != "microsoft.keyvault"
}

keySource {
    lower(input.resources[_].type) == "microsoft.storage/storageaccounts"
    not azure_attribute_absence["keySource"]
    not azure_issue["keySource"]
}

keySource = false {
    azure_issue["keySource"]
}

keySource = false {
    azure_attribute_absence["keySource"]
}

keySource_err = "Critical data storage in Storage Account is currently not encrypted with Customer Managed Key" {
    azure_issue["keySource"]
}

keySource_miss_err = "Storage Account encryption property 'keySource' is missing from the resource" {
    azure_attribute_absence["keySource"]
}


keySource_metadata := {
    "Policy Code": "PR-AZR-0114-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure critical data storage in Storage Account is encrypted with Customer Managed Key",
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
    not resource.location
}

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

region_err = "Storage Accounts location configuration is currenly not inside of Europe" {
    azure_issue["region"]
}

region_metadata := {
    "Policy Code": "PR-AZR-0122-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Storage Accounts location configuration should be inside of Europe",
    "Policy Description": "Identify Storage Accounts outside of the following regions: northeurope, westeurope",
    "Resource Type": "microsoft.storage/storageaccounts",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts"
}


# PR-AZR-0123-ARM

default blobServicePublicAccessDisabled = null

azure_issue["blobServicePublicAccessDisabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not resource.properties.allowBlobPublicAccess
}

azure_issue["blobServicePublicAccessDisabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    resource.properties.allowBlobPublicAccess == true
}

blobServicePublicAccessDisabled {
    lower(input.resources[_].type) == "microsoft.storage/storageaccounts"
    not azure_issue["blobServicePublicAccessDisabled"]
}

blobServicePublicAccessDisabled = false {
    azure_issue["blobServicePublicAccessDisabled"]
}

blobServicePublicAccessDisabled_err = "Storage Account currently allowing public access to all blobs or containers" {
    azure_issue["blobServicePublicAccessDisabled"]
}

blobServicePublicAccessDisabled_metadata := {
    "Policy Code": "PR-AZR-0113-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure that Storage Account should not allow public access to all blobs or containers",
    "Policy Description": "This policy will identify which Storage Account has public access enabled for all blobs or containers",
    "Resource Type": "microsoft.storage/storageaccounts",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts"
}



 # PR-AZR-0148-ARM

default storage_acount_by_pass = null

azure_attribute_absence["storage_acount_by_pass"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not resource.properties.networkAcls.bypass
}

azure_issue["storage_acount_by_pass"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    lower(resource.properties.networkAcls.bypass) != "azureservices"
}

storage_acount_by_pass {
    lower(input.resources[_].type) == "microsoft.storage/storageaccounts"
    not azure_attribute_absence["storage_acount_by_pass"]
    not azure_issue["storage_acount_by_pass"]
}

storage_acount_by_pass = false {
    azure_issue["storage_acount_by_pass"]
}

storage_acount_by_pass = false {
    azure_attribute_absence["storage_acount_by_pass"]
}

storage_acount_by_pass_err = "microsoft.storage/storageaccounts resource property networkAcls.bypass missing in the resource" {
    azure_attribute_absence["storage_acount_by_pass"]
} else = "Azure Storage Account Trusted Microsoft Services access is not enabled" {
    azure_issue["storage_acount_by_pass"]
}


storage_acount_by_pass_metadata := {
    "Policy Code": "PR-AZR-0148-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Storage Account Trusted Microsoft Services access should be enabled",
    "Policy Description": "Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are any combination of Logging, Metrics, AzureServices (For example, 'Logging, Metrics'), or None to bypass none of those traffics. - None, Logging, Metrics, AzureServices.",
    "Resource Type": "microsoft.storage/storageaccounts",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts"
}