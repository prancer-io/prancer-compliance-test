package rule

# https://docs.microsoft.com/en-us/rest/api/storagerp/storage-accounts/get-properties

#
# PR-AZR-STR-003
#

default storage_secure = null

azure_attribute_absence["storage_secure"] {
    not input.properties.supportsHttpsTrafficOnly
}

azure_issue["storage_secure"] {
    input.properties.supportsHttpsTrafficOnly == false
}


storage_secure {
    azure_attribute_absence["storage_secure"]
    not azure_issue["storage_secure"]
}

storage_secure = false {
    azure_issue["storage_secure"]
}


storage_secure_err = "Storage Accounts https based secure transfer is not enabled" {
    azure_issue["storage_secure"]
}


storage_secure_metadata := {
    "Policy Code": "PR-AZR-STR-003",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Storage Accounts https based secure transfer should be enabled",
    "Policy Description": "The secure transfer option enhances the security of your storage account by only allowing requests to the storage account by a secure connection. For example, when calling REST APIs to access your storage accounts, you must connect using HTTPs. Any requests using HTTP will be rejected when 'secure transfer required' is enabled. When you are using the Azure files service, connection without encryption will fail, including scenarios using SMB 2.1, SMB 3.0 without encryption, and some flavors of the Linux SMB client. Because Azure storage doesnâ€™t support HTTPs for custom domain names, this option is not applied when using a custom domain name.",
    "Resource Type": "microsoft.storage/storageaccounts",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/rest/api/storagerp/storage-accounts/get-properties"
}

#
# PR-AZR-STR-004
#

default storage_acl = null

azure_attribute_absence["storage_acl"] {
    not input.properties.networkAcls.defaultAction
}


azure_issue["storage_acl"] {
    lower(input.properties.networkAcls.defaultAction) != "deny"
}


storage_acl {
    not azure_attribute_absence["storage_acl"]
    not azure_issue["storage_acl"]
}

storage_acl = false {
    azure_issue["storage_acl"]
}

storage_acl = false {
    azure_attribute_absence["storage_acl"]
}

storage_acl_err = "Storage Account attribute networkAcls.defaultAction is missing from the resource" {
    azure_attribute_absence["storage_acl"]
} else = "Storage Accounts firewall rule is currently not enabled" {
    azure_issue["storage_acl"]
}


storage_acl_metadata := {
    "Policy Code": "PR-AZR-STR-004",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Storage Accounts should have firewall rules enabled",
    "Policy Description": "Turning on firewall rules for your storage account blocks incoming requests for data by default, unless the requests come from a service that is operating within an Azure Virtual Network (VNet). Requests that are blocked include those from other Azure services, from the Azure portal, from logging and metrics services, and so on.<br><br>You can grant access to Azure services that operate from within a VNet by allowing the subnet of the service instance. Enable a limited number of scenarios through the Exceptions mechanism described in the following section. To access the Azure portal, you would need to be on a machine within the trusted boundary (either IP or VNet) that you set up.",
    "Resource Type": "microsoft.storage/storageaccounts",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/rest/api/storagerp/storage-accounts/get-properties"
}


# PR-AZR-STR-006

default blobService = null

azure_attribute_absence["blobService"] {
    not input.properties.encryption.services.blob.enabled
}

azure_issue["blobService"] {
    input.properties.encryption.services.blob.enabled != true
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
    "Policy Code": "PR-AZR-STR-006",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Ensure that 'Storage service encryption' is enabled for the Blob Service",
    "Policy Description": "Enable data encryption at rest for blobs. Storage service encryption protects your data at rest. Azure Storage encrypts data when it's written, and automatically decrypts it when it is accessed.",
    "Resource Type": "microsoft.storage/storageaccounts",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/rest/api/storagerp/storage-accounts/get-properties"
}

# PR-AZR-STR-007

default fileService = null

azure_attribute_absence["fileService"] {
    not input.properties.encryption.services.file.enabled
}

azure_issue["fileService"] {
    input.properties.encryption.services.file.enabled != true
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
    "Policy Code": "PR-AZR-STR-007",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Ensure that 'Storage service encryption' is enabled for the File Service",
    "Policy Description": "Azure Storage encryption protects your data and to help you to meet your organizational security and compliance commitments. Data in Azure Storage is encrypted and decrypted transparently using 256-bit AES encryption, one of the strongest block ciphers available, and is FIPS 140-2 compliant. Azure Storage encryption is similar to BitLocker encryption on Windows.",
    "Resource Type": "microsoft.storage/storageaccounts",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/rest/api/storagerp/storage-accounts/get-properties"
}



# PR-AZR-STR-008

default keySource = null

azure_attribute_absence["keySource"] {
    not input.properties.encryption.keySource
}

azure_issue["keySource"] {
    lower(resource.properties.encryption.keySource) != "microsoft.keyvault"
}


keySource {
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
    azure_attribute_absence["keySource"]
} else = "Critical data storage in Storage Account is currently not encrypted with Customer Managed Key" {
    azure_issue["keySource"]
}


keySource_metadata := {
    "Policy Code": "PR-AZR-STR-008",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Ensure critical data storage in Storage Account is encrypted with Customer Managed Key",
    "Policy Description": "By default, data in the storage account is encrypted using Microsoft Managed Keys at rest. All Azure Storage resources are encrypted, including blobs, disks, files, queues, and tables. All object metadata is also encrypted. However, if you want to control and manage this encryption key yourself, you can specify a customer-managed key, that key is used to protect and control access to the key that encrypts your data. You can also choose to automatically update the key version used for Azure Storage encryption whenever a new version is available in the associated Key Vault.",
    "Resource Type": "microsoft.storage/storageaccounts",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/rest/api/storagerp/storage-accounts/get-properties"
}


# PR-AZR-STR-009

default region = null


azure_issue["region"] {
    lower(input.location) != "northeurope"
    lower(input.location) != "westeurope"
}


region {
    not azure_issue["region"]
}

region = false {
    azure_issue["region"]
}

region_err = "Storage Accounts location configuration is currenly not inside of Europe" {
    azure_issue["region"]
}

region_metadata := {
    "Policy Code": "PR-AZR-STR-009",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Storage Accounts location configuration should be inside of Europe",
    "Policy Description": "Identify Storage Accounts outside of the following regions: northeurope, westeurope",
    "Resource Type": "microsoft.storage/storageaccounts",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/rest/api/storagerp/storage-accounts/get-properties"
}


# PR-AZR-STR-010

default blobServicePublicAccessDisabled = null

azure_issue["blobServicePublicAccessDisabled"] {
    not input.properties.allowBlobPublicAccess
}

azure_issue["blobServicePublicAccessDisabled"] {
    input.properties.allowBlobPublicAccess == true
}


blobServicePublicAccessDisabled {
    not azure_issue["blobServicePublicAccessDisabled"]
}

blobServicePublicAccessDisabled = false {
    azure_issue["blobServicePublicAccessDisabled"]
}

blobServicePublicAccessDisabled_err = "Storage Account currently allowing public access to all blobs or containers" {
    azure_issue["blobServicePublicAccessDisabled"]
}

blobServicePublicAccessDisabled_metadata := {
    "Policy Code": "PR-AZR-STR-010",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Ensure that Storage Account should not allow public access to all blobs or containers",
    "Policy Description": "This policy will identify which Storage Account has public access enabled for all blobs or containers",
    "Resource Type": "microsoft.storage/storageaccounts",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/rest/api/storagerp/storage-accounts/get-properties"
}



 # PR-AZR-ARM-STR-011

default storage_acount_by_pass = null

azure_attribute_absence["storage_acount_by_pass"] {
    not input.properties.networkAcls.bypass
}


azure_issue["storage_acount_by_pass"] {
    lower(input.properties.networkAcls.bypass) != "azureservices"
}


storage_acount_by_pass {
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
    "Policy Code": "PR-AZR-STR-011",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure Storage Account Trusted Microsoft Services access should be enabled",
    "Policy Description": "Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are any combination of Logging, Metrics, AzureServices (For example, 'Logging, Metrics'), or None to bypass none of those traffics. - None, Logging, Metrics, AzureServices.",
    "Resource Type": "microsoft.storage/storageaccounts",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/rest/api/storagerp/storage-accounts/get-properties"
}