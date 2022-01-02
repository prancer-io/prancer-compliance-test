package rule

has_property(parent_object, target_property) { 
	_ = parent_object[target_property]
}

# https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts

#
# PR-AZR-CLD-STR-003
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
    "Policy Code": "PR-AZR-CLD-STR-003",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Storage Accounts https based secure transfer should be enabled",
    "Policy Description": "The secure transfer option enhances the security of your storage account by only allowing requests to the storage account by a secure connection. For example, when calling REST APIs to access your storage accounts, you must connect using HTTPS. Any requests using HTTP will be rejected when 'secure transfer required' is enabled. When you are using the Azure files service, connection without encryption will fail, including scenarios using SMB 2.1, SMB 3.0 without encryption, and some flavors of the Linux SMB client. Because Azure storage doesn't support HTTPS for custom domain names, this option is not applied when using a custom domain name.",
    "Resource Type": "microsoft.storage/storageaccounts",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts"
}

#
# PR-AZR-CLD-STR-004
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
    "Policy Code": "PR-AZR-CLD-STR-004",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Storage Accounts should have firewall rules enabled",
    "Policy Description": "Turning on firewall rules for your storage account blocks incoming requests for data by default, unless the requests come from a service that is operating within an Azure Virtual Network (VNet). Requests that are blocked include those from other Azure services, from the Azure portal, from logging and metrics services, and so on.<br><br>You can grant access to Azure services that operate from within a VNet by allowing the subnet of the service instance. Enable a limited number of scenarios through the Exceptions mechanism described in the following section. To access the Azure portal, you would need to be on a machine within the trusted boundary (either IP or VNet) that you set up.",
    "Resource Type": "microsoft.storage/storageaccounts",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts"
}

# https://docs.microsoft.com/en-us/azure/templates/microsoft.security/advancedthreatprotectionsettings?tabs=json
# Advanced Threat Protection should be enabled for storage account
# PR-AZR-CLD-STR-005

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
    "Policy Code": "PR-AZR-CLD-STR-005",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Advanced Threat Protection should be enabled for storage account",
    "Policy Description": "Advanced Threat Protection should be enabled for all the storage accounts",
    "Resource Type": "microsoft.storage/storageaccounts",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts"
}


# https://azure.microsoft.com/en-us/blog/announcing-default-encryption-for-azure-blobs-files-table-and-queue-storage/
# This feature is enabled by default thats why Terraform does not have any property for that
# PR-AZR-CLD-STR-006

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
    "Policy Code": "PR-AZR-CLD-STR-006",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Ensure that 'Storage service encryption' is enabled for the Blob Service",
    "Policy Description": "Enable data encryption at rest for blobs. Storage service encryption protects your data at rest. Azure Storage encrypts data when it's written, and automatically decrypts it when it is accessed.",
    "Resource Type": "microsoft.storage/storageaccounts",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts"
}

# https://azure.microsoft.com/en-us/blog/announcing-default-encryption-for-azure-blobs-files-table-and-queue-storage/
# This feature is enabled by default thats why Terraform does not have any property for that
# PR-AZR-CLD-STR-007

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
    "Policy Code": "PR-AZR-CLD-STR-007",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Ensure that 'Storage service encryption' is enabled for the File Service",
    "Policy Description": "Azure Storage encryption protects your data and helps you to meet your organizational security and compliance commitments. Data in Azure Storage is encrypted and decrypted transparently using 256-bit AES encryption, one of the strongest block ciphers available, and is FIPS 140-2 compliant. Azure Storage encryption is similar to BitLocker encryption on Windows.",
    "Resource Type": "microsoft.storage/storageaccounts",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts"
}



# https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts
# PR-AZR-CLD-STR-008

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
    "Policy Code": "PR-AZR-CLD-STR-008",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Ensure critical data storage in Storage Account is encrypted with Customer Managed Key",
    "Policy Description": "By default, data in the storage account is encrypted using Microsoft Managed Keys at rest. All Azure Storage resources are encrypted, including blobs, disks, files, queues, and tables. All object metadata is also encrypted. However, if you want to control and manage this encryption key yourself, you can specify a customer-managed key, that key is used to protect and control access to the key that encrypts your data. You can also choose to automatically update the key version used for Azure Storage encryption whenever a new version is available in the associated Key Vault.",
    "Resource Type": "microsoft.storage/storageaccounts",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts"
}


# PR-AZR-CLD-STR-009

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
    "Policy Code": "PR-AZR-CLD-STR-009",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Storage Accounts location configuration should be inside of Europe",
    "Policy Description": "Identify Storage Accounts outside of the following regions: northeurope, westeurope",
    "Resource Type": "microsoft.storage/storageaccounts",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts"
}


# PR-AZR-CLD-STR-010

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
    "Policy Code": "PR-AZR-CLD-STR-010",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Ensure that Storage Account should not allow public access to all blobs or containers",
    "Policy Description": "This policy will identify which Storage Account has public access enabled for all blobs or containers",
    "Resource Type": "microsoft.storage/storageaccounts",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts"
}



 # PR-AZR-CLD-STR-011

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
    "Policy Code": "PR-AZR-CLD-STR-011",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure Storage Account Trusted Microsoft Services access should be enabled",
    "Policy Description": "Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are any combination of Logging, Metrics, AzureServices (For example, 'Logging, Metrics'), or None to bypass none of those traffics. - None, Logging, Metrics, AzureServices.",
    "Resource Type": "microsoft.storage/storageaccounts",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts"
}


# PR-AZR-CLD-STR-018
#

default storage_account_latest_tls_configured = null

#default to TLS1_0
azure_attribute_absence["storage_account_latest_tls_configured"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not resource.properties.minimumTlsVersion
}

azure_issue["storage_account_latest_tls_configured"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    lower(resource.properties.minimumTlsVersion) != "tls1_2"
}


storage_account_latest_tls_configured {
    lower(input.resources[_].type) == "microsoft.storage/storageaccounts"
    not azure_attribute_absence["storage_account_latest_tls_configured"]
    not azure_issue["storage_account_latest_tls_configured"]
}

storage_account_latest_tls_configured = false {
    azure_attribute_absence["storage_account_latest_tls_configured"]
}

storage_account_latest_tls_configured = false {
    azure_issue["storage_account_latest_tls_configured"]
}

storage_account_latest_tls_configured_err = "Azure Storage Account currently dont have latest version of tls configured" {
    azure_issue["storage_account_latest_tls_configured"]
} else = "microsoft.storage/storageaccounts property 'minimumTlsVersion' need to be exist. Its missing from the resource. Please set the value to 'TLS1_2' after property addition." {
    azure_attribute_absence["storage_account_latest_tls_configured"]
}

storage_account_latest_tls_configured_metadata := {
    "Policy Code": "PR-AZR-CLD-STR-018",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Ensure Azure Storage Account has latest version of tls configured",
    "Policy Description": "This policy will identify the Azure Storage Account which don't have the latest version of tls configured and give the alert",
    "Resource Type": "microsoft.storage/storageaccounts",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts"
}

# PR-AZR-CLD-STR-019
#
default storage_account_private_endpoint = null

azure_attribute_absence["storage_account_private_endpoint"] {
    count([c | lower(input.resources[_].type) == "microsoft.network/privateendpoints"; c := 1]) == 0
}

no_azure_issue["storage_account_private_endpoint"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/privateendpoints"
    privateLinkServiceConnection := resource.properties.privateLinkServiceConnections[_]
    contains(lower(privateLinkServiceConnection.properties.privateLinkServiceId), "microsoft.storage/storageaccounts")
}


storage_account_private_endpoint {
	lower(input.resources[_].type) == "microsoft.storage/storageaccounts"
    no_azure_issue["storage_account_private_endpoint"]
    not azure_attribute_absence["storage_account_private_endpoint"]
}

storage_account_private_endpoint = false {
	lower(input.resources[_].type) == "microsoft.storage/storageaccounts"
    not no_azure_issue["storage_account_private_endpoint"]
}

storage_account_private_endpoint = false {
	lower(input.resources[_].type) == "microsoft.storage/storageaccounts"
    azure_attribute_absence["storage_account_private_endpoint"]
}

storage_account_private_endpoint_err = "Azure Storage Account does not configure with private endpoints" {
	lower(input.resources[_].type) == "microsoft.storage/storageaccounts"
    not no_azure_issue["storage_account_private_endpoint"]
} else = "Azure Private endpoints resoruce is missing" {
	lower(input.resources[_].type) == "microsoft.storage/storageaccounts"
    azure_attribute_absence["storage_account_private_endpoint"]
}

storage_account_private_endpoint_metadata := {
    "Policy Code": "PR-AZR-CLD-STR-019",
    "Type": "Cloud",  
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Storage accounts should use private link",
    "Policy Description": "Azure Private Link lets you connect your virtual network to Azure services without a public IP address at the source or destination. The Private Link platform handles the connectivity between the consumer and services over the Azure backbone network. By mapping private endpoints to your storage account, data leakage risks are reduced. Learn more about private links at - https://aka.ms/azureprivatelinkoverview",
    "Resource Type": "microsoft.storage/storageaccounts",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts"
}


#
# PR-AZR-CLD-STR-020
#

default storage_account_require_encryption = null

azure_attribute_absence["storage_account_require_encryption"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not resource.properties.encryption.requireInfrastructureEncryption
}


azure_issue["storage_account_require_encryption"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    resource.properties.encryption.requireInfrastructureEncryption != true
}


storage_account_require_encryption {
    lower(input.resources[_].type) == "microsoft.storage/storageaccounts"
    not azure_issue["storage_account_require_encryption"]
    not azure_attribute_absence["storage_account_require_encryption"]
}

storage_account_require_encryption = false {
    azure_issue["storage_account_require_encryption"]
}

storage_account_require_encryption = false {
    azure_attribute_absence["storage_account_require_encryption"]
}

storage_account_require_encryption_err = "Storage account encryption scopes currently disabled for double encryption for data at rest" {
    azure_issue["storage_account_require_encryption"]
} else = "microsoft.storage/storageaccounts property 'encryption.requireInfrastructureEncryption' need to be exist. Its missing from the resource. Please set the value to 'true' after property addition." {
    azure_attribute_absence["storage_account_require_encryption"]
}


storage_account_require_encryption_metadata := {
    "Policy Code": "PR-AZR-CLD-STR-020",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Storage accounts should have infrastructure encryption",
    "Policy Description": "Enable infrastructure encryption for a higher level of assurance that the data is secure. When infrastructure encryption is enabled, data in a storage account is encrypted twice.",
    "Resource Type": "microsoft.storage/storageaccounts",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts"
}

#
# PR-AZR-CLD-STR-021
#

default storage_account_scopes_require_encryption = null

azure_attribute_absence["storage_account_scopes_require_encryption"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts/encryptionscopes"
    not resource.properties.requireInfrastructureEncryption
}


azure_issue["storage_account_scopes_require_encryption"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts/encryptionscopes"
    resource.properties.requireInfrastructureEncryption != true
}



storage_account_scopes_require_encryption {
    lower(input.resources[_].type) == "microsoft.storage/storageaccounts/encryptionscopes"
    not azure_issue["storage_account_scopes_require_encryption"]
    not azure_attribute_absence["storage_account_scopes_require_encryption"]
}

storage_account_scopes_require_encryption = false {
    azure_issue["storage_account_scopes_require_encryption"]
}

storage_account_scopes_require_encryption = false {
    azure_attribute_absence["storage_account_scopes_require_encryption"]
}

storage_account_scopes_require_encryption_err = "Storage account encryption scopes currently disabled for double encryption for data at rest" {
    azure_issue["storage_account_scopes_require_encryption"]
} else = "microsoft.storage/storageaccounts/encryptionscopes property 'requireInfrastructureEncryption' need to be exist. Its missing from the resource. Please set the value to 'true' after property addition." {
    azure_attribute_absence["storage_account_scopes_require_encryption"]
}


storage_account_scopes_require_encryption_metadata := {
    "Policy Code": "PR-AZR-CLD-STR-021",
    "Type": "Cloud",  
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Storage account encryption scopes should have infrastructure encryption",
    "Policy Description": "Enable infrastructure encryption for encryption at the rest of your storage account encryption scopes for added security. Infrastructure encryption ensures that your data is encrypted twice.",
    "Resource Type": "microsoft.storage/storageaccounts/encryptionscopes",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts/encryptionscopes"
}

# PR-AZR-CLD-STR-022
#

default storage_account_encryption_scopes_source = null

azure_attribute_absence["storage_account_encryption_scopes_source"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts/encryptionscopes"
    not resource.properties.source
}


azure_issue["storage_account_encryption_scopes_source"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts/encryptionscopes"
    lower(resource.properties.source) != "microsoft.keyvault"
}


storage_account_encryption_scopes_source {
    lower(input.resources[_].type) == "microsoft.storage/storageaccounts/encryptionscopes"
    not azure_issue["storage_account_encryption_scopes_source"]
    not azure_attribute_absence["storage_account_encryption_scopes_source"]
}

storage_account_encryption_scopes_source = false {
    azure_issue["storage_account_encryption_scopes_source"]
}

storage_account_encryption_scopes_source = false {
    azure_attribute_absence["storage_account_encryption_scopes_source"]
}

storage_account_encryption_scopes_source_err = "Critical data storage in Storage Account Encryption Scopes is currently not encrypted with Customer Managed Key" {
    azure_issue["storage_account_encryption_scopes_source"]
} else = "microsoft.storage/storageaccounts/encryptionscopes property 'source' need to be exist. Its missing from the resource. Please set the value to 'microsoft.keyvault' after property addition." {
    azure_attribute_absence["storage_account_encryption_scopes_source"]
}


storage_account_encryption_scopes_source_metadata := {
    "Policy Code": "PR-AZR-CLD-STR-022",
    "Type": "Cloud",  
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Storage account encryption scopes should use customer-managed keys to encrypt data at rest",
    "Policy Description": "Use customer-managed keys to manage the encryption at the rest of your storage account encryption scopes. Customer-managed keys enable the data to be encrypted with an Azure key-vault key created and owned by you. You have full control and responsibility for the key lifecycle, including rotation and management. Learn more about storage account encryption scopes at https://aka.ms/encryption-scopes-overview.",
    "Resource Type": "microsoft.storage/storageaccounts/encryptionscopes",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts/encryptionscopes"
}

#
# PR-AZR-CLD-STR-023
#

default storage_vnet_service_endpoint = null

azure_attribute_absence["storage_vnet_service_endpoint"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not resource.properties.networkAcls.defaultAction
}


azure_attribute_absence["storage_vnet_service_endpoint"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not resource.properties.networkAcls.virtualNetworkRules
}


azure_issue["storage_vnet_service_endpoint"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    lower(resource.properties.networkAcls.defaultAction) != "deny"
}


azure_issue["storage_vnet_service_endpoint"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    virtualNetworkRule := resource.properties.networkAcls.virtualNetworkRules[_]
    count(virtualNetworkRule.id) == 0
}


storage_vnet_service_endpoint {
    lower(input.resources[_].type) == "microsoft.storage/storageaccounts"
    not azure_attribute_absence["storage_vnet_service_endpoint"]
    not azure_issue["storage_vnet_service_endpoint"]
}

storage_vnet_service_endpoint = false {
    azure_issue["storage_vnet_service_endpoint"]
}

storage_vnet_service_endpoint = false {
    azure_attribute_absence["storage_vnet_service_endpoint"]
}

storage_vnet_service_endpoint_err = "Storage Accounts firewall rule is currently not enabled" {
    azure_issue["storage_vnet_service_endpoint"]
} else = "Storage Account attribute networkAcls.defaultAction or networkAcls.virtualNetworkRules.id is missing from the resource" {
    azure_attribute_absence["storage_vnet_service_endpoint"]
}

storage_vnet_service_endpoint_metadata := {
    "Policy Code": "PR-AZR-CLD-STR-023",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Storage Accounts should use a virtual network service endpoint",
    "Policy Description": "This policy audits any Storage Account not configured to use a virtual network service endpoint.",
    "Resource Type": "microsoft.storage/storageaccounts",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts"
}


#
# PR-AZR-CLD-STR-024
#


default storage_account_allow_shared_key_access = null

azure_attribute_absence["storage_account_allow_shared_key_access"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not has_property(resource.properties,"allowSharedKeyAccess")
}


azure_issue["storage_account_allow_shared_key_access"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    resource.properties.allowSharedKeyAccess != false
}


storage_account_allow_shared_key_access {
    lower(input.resources[_].type) == "microsoft.storage/storageaccounts"
    not azure_issue["storage_account_allow_shared_key_access"]
    not azure_attribute_absence["storage_account_allow_shared_key_access"]
}

storage_account_allow_shared_key_access = false {
    azure_issue["storage_account_allow_shared_key_access"]
}

storage_account_allow_shared_key_access = false {
    azure_attribute_absence["storage_account_allow_shared_key_access"]
}

storage_account_allow_shared_key_access_err = "Storage accounts currently use shared key access" {
    azure_issue["storage_account_allow_shared_key_access"]
} else = "microsoft.storage/storageaccounts property 'allowSharedKeyAccess' need to be exist. Its missing from the resource. Please set the value to 'false' after property addition." {
    azure_attribute_absence["storage_account_allow_shared_key_access"]
}


storage_account_allow_shared_key_access_metadata := {
    "Policy Code": "PR-AZR-CLD-STR-024",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Storage accounts should prevent shared key access",
    "Policy Description": "Audit requirement of Azure Active Directory (Azure AD) to authorize requests for your storage account. By default, requests can be authorized with either Azure Active Directory credentials or by using the account access key for Shared Key authorization. Of these two types of authorization, Azure AD provides superior security and ease of use over Shared Key and is recommended by Microsoft.",
    "Resource Type": "microsoft.storage/storageaccounts",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts"
}