package rule

has_property(parent_object, target_property) { 
	_ = parent_object[target_property]
}

array_contains(target_array, element) = true {
  lower(target_array[_]) == lower(element)
} else = false { true }

storage_account_need_to_skip(target_storage_account_resource) {
    count([c | r := input.resources[_];
              lower(r.type) == "microsoft.storage/storageaccounts/blobservices/containers";
              array_contains(r.dependsOn, concat("/", [target_storage_account_resource.type, target_storage_account_resource.name]));
              contains(lower(r.name), "bootdiagnostics");
              c := 1]) > 0
}

storage_account_need_to_skip(target_storage_account_resource) {
    count([c | r := input.resources[_];
              lower(r.type) == "microsoft.storage/storageaccounts/blobservices/containers";
              array_contains(r.dependsOn, concat("/", [target_storage_account_resource.type, target_storage_account_resource.name]));
              contains(lower(r.name), "insights-logs-networksecuritygroupflowevent");
              c := 1]) > 0
}

storage_account_need_to_skip(target_storage_account_resource) {
    has_property(target_storage_account_resource.tags, "ms-resource-usage")
    lower(target_storage_account_resource.tags["ms-resource-usage"]) == "azure-cloud-shell"
}

# https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts/blobservices

#
# PR-AZR-ARM-STR-001
#
# SideNote for Reference: This cannot be done via Terraform. terraform can only change retention days.
# See the note section at https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account#container_delete_retention_policy
# Note is applicable for delete_retention_policy as well.
default storage_blob_soft_delete = null

azure_attribute_absence["storage_blob_soft_delete"] {
    count([c | lower(input.resources[_].type) == "microsoft.storage/storageaccounts/blobservices"; c := 1]) == 0
}

azure_attribute_absence["storage_blob_soft_delete"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts/blobservices"
    not has_property(resource.properties.deleteRetentionPolicy, "enabled")
}

azure_issue["storage_blob_soft_delete"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    count([c | r := input.resources[_];
              lower(r.type) == "microsoft.storage/storageaccounts/blobservices";
              array_contains(r.dependsOn, concat("/", [resource.type, resource.name]));
              r.properties.deleteRetentionPolicy.enabled;
              c := 1]) == 0
}

storage_blob_soft_delete {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    not azure_attribute_absence["storage_blob_soft_delete"]
    not azure_issue["storage_blob_soft_delete"]
}

storage_blob_soft_delete = false {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    azure_attribute_absence["storage_blob_soft_delete"]
}

storage_blob_soft_delete = false {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    azure_issue["storage_blob_soft_delete"]
}

storage_blob_soft_delete_err = "microsoft.storage/storageaccounts/blobservices resource property deleteRetentionPolicy.enabled is missing." {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    azure_attribute_absence["storage_blob_soft_delete"]
} else = "Soft delete on blob service should be enabled" {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    azure_issue["storage_blob_soft_delete"]
}

storage_blob_soft_delete_metadata := {
    "Policy Code": "PR-AZR-ARM-STR-001",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Soft delete on blob service should be enabled",
    "Policy Description": "The blob service properties for blob soft delete. It helps to restore removed blob within configured retention days",
    "Resource Type": "microsoft.storage/storageaccounts/blobservices",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts/blobservices"
}


#
# PR-AZR-ARM-STR-002
#
# SideNote for Reference: This cannot be done via Terraform. terraform can only change retention days.
# See the note section at https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account#container_delete_retention_policy
default storage_blob_container_soft_delete = null

azure_attribute_absence["storage_blob_container_soft_delete"] {
    count([c | lower(input.resources[_].type) == "microsoft.storage/storageaccounts/blobservices"; c := 1]) == 0
}

azure_attribute_absence["storage_blob_container_soft_delete"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts/blobservices"
    not has_property(resource.properties.containerDeleteRetentionPolicy, "enabled")
}

azure_issue["storage_blob_container_soft_delete"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    count([c | r := input.resources[_];
              lower(r.type) == "microsoft.storage/storageaccounts/blobservices";
              array_contains(r.dependsOn, concat("/", [resource.type, resource.name]));
              r.properties.containerDeleteRetentionPolicy.enabled;
              c := 1]) == 0
}

storage_blob_container_soft_delete {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    not azure_attribute_absence["storage_blob_container_soft_delete"]
    not azure_issue["storage_blob_container_soft_delete"]
}

storage_blob_container_soft_delete = false {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    azure_attribute_absence["storage_blob_container_soft_delete"]
}

storage_blob_container_soft_delete = false {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    azure_issue["storage_blob_container_soft_delete"]
}

storage_blob_container_soft_delete_err = "microsoft.storage/storageaccounts/blobservices resource property containerDeleteRetentionPolicy.enabled is missing." {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    azure_attribute_absence["storage_blob_container_soft_delete"]
} else = "Soft delete on blob service container should be enabled" {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    azure_issue["storage_blob_container_soft_delete"]
}

storage_blob_container_soft_delete_metadata := {
    "Policy Code": "PR-AZR-ARM-STR-002",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Soft delete on blob service container should be enabled",
    "Policy Description": "The blob service properties for container soft delete. It helps to restore removed blob containers within configured retention days.",
    "Resource Type": "microsoft.storage/storageaccounts/blobservices",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts/blobservices"
}


# https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts

#
# PR-AZR-ARM-STR-003
#

default storage_secure = null

#in latest API from 2019-04-01, supportsHttpsTrafficOnly is true by default if not exist
azure_attribute_absence_new["storage_secure"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    resource.apiVersion >= "2019-04-01"
    not resource.properties.supportsHttpsTrafficOnly
}

source_path[{"storage_secure":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    resource.apiVersion >= "2019-04-01"
    not resource.properties.supportsHttpsTrafficOnly
    metadata:= {
        "resource_path": [["resources",i,"properties","supportsHttpsTrafficOnly"]]
    }
}

#in older API before 2019-04-01, supportsHttpsTrafficOnly is false by default if not exist
azure_attribute_absence_old["storage_secure"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    resource.apiVersion < "2019-04-01"
    not resource.properties.supportsHttpsTrafficOnly
}

source_path[{"storage_secure":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    resource.apiVersion < "2019-04-01"
    not resource.properties.supportsHttpsTrafficOnly
    metadata:= {
        "resource_path": [["resources",i,"properties","supportsHttpsTrafficOnly"]]
    }
}

azure_issue["storage_secure"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    resource.properties.supportsHttpsTrafficOnly == false
}

source_path[{"storage_secure":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    resource.properties.supportsHttpsTrafficOnly == false
    metadata:= {
        "resource_path": [["resources",i,"properties","supportsHttpsTrafficOnly"]]
    }
}

storage_secure {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    not azure_attribute_absence_old["storage_secure"]
    not azure_issue["storage_secure"]
}

storage_secure {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    azure_attribute_absence_new["storage_secure"]
    not azure_issue["storage_secure"]
}

storage_secure = false {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    azure_issue["storage_secure"]
}

storage_secure = false {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    azure_attribute_absence_old["storage_secure"]
}

storage_secure_err = "Storage Accounts https based secure transfer is not enabled" {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    azure_issue["storage_secure"]
}

storage_secure_metadata := {
    "Policy Code": "PR-AZR-ARM-STR-003",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Storage Accounts https based secure transfer should be enabled",
    "Policy Description": "The secure transfer option enhances the security of your storage account by only allowing requests to the storage account by a secure connection. For example, when calling REST APIs to access your storage accounts, you must connect using HTTPS. Any requests using HTTP will be rejected when 'secure transfer required' is enabled. When you are using the Azure files service, connection without encryption will fail, including scenarios using SMB 2.1, SMB 3.0 without encryption, and some flavors of the Linux SMB client. Because Azure storage doesn't support HTTPS for custom domain names, this option is not applied when using a custom domain name.",
    "Resource Type": "microsoft.storage/storageaccounts",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts"
}

#
# PR-AZR-ARM-STR-004
#

default storage_acl = null

azure_attribute_absence["storage_acl"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    not resource.properties.networkAcls.defaultAction
}

source_path[{"storage_acl":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    not resource.properties.networkAcls.defaultAction
    metadata:= {
        "resource_path": [["resources",i,"properties","networkAcls","defaultAction"]]
    }
}

azure_issue["storage_acl"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    lower(resource.properties.networkAcls.defaultAction) != "deny"
}

source_path[{"storage_acl":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    lower(resource.properties.networkAcls.defaultAction) != "deny"
    metadata:= {
        "resource_path": [["resources",i,"properties","networkAcls","defaultAction"]]
    }
}

storage_acl {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    not azure_attribute_absence["storage_acl"]
    not azure_issue["storage_acl"]
}

storage_acl = false {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    azure_issue["storage_acl"]
}

storage_acl = false {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    azure_attribute_absence["storage_acl"]
}

storage_acl_err = "Storage Accounts firewall rule is currently not enabled" {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    azure_issue["storage_acl"]
} else = "Storage Account attribute networkAcls.defaultAction is missing from the resource" {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    azure_attribute_absence["storage_acl"]
}

storage_acl_metadata := {
    "Policy Code": "PR-AZR-ARM-STR-004",
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
# PR-AZR-ARM-STR-005

default storage_threat_protection = null

azure_issue["storage_threat_protection"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    #nested := input.resources[_]
    #lower(nested.type) == "providers/advancedthreatprotectionsettings"
    #nested.properties.isEnabled != true
    nested_type := "providers/advancedthreatprotectionsettings"
    count([ c | lower(resource.resources[_].type) == nested_type; c = 1]) == 0
}

source_path[{"storage_threat_protection":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    nested_type := "providers/advancedthreatprotectionsettings"
    resources := resource.resources[j]
    count([ c | lower(resources.type) == nested_type; c = 1]) == 0
    metadata:= {
        "resource_path": [["resources",i,"resources",j,"type"]]
    }
}

azure_issue["storage_threat_protection"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    nested := resource.resources[_]
    lower(nested.type) == "providers/advancedthreatprotectionsettings"
    not nested.properties.isEnabled
}

source_path[{"storage_threat_protection":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    nested := resource.resources[j]
    lower(nested.type) == "providers/advancedthreatprotectionsettings"
    not nested.properties.isEnabled
    metadata:= {
        "resource_path": [["resources",i,"resources",j,"properties","isEnabled"]]
    }
}

azure_issue["storage_threat_protection"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    nested := resource.resources[_]
    lower(nested.type) == "providers/advancedthreatprotectionsettings"
    nested.properties.isEnabled != true
}

source_path[{"storage_threat_protection":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    nested := resource.resources[j]
    lower(nested.type) == "providers/advancedthreatprotectionsettings"
    nested.properties.isEnabled != true
    metadata:= {
        "resource_path": [["resources",i,"resources",j,"properties","isEnabled"]]
    }
}

storage_threat_protection {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    not azure_issue["storage_threat_protection"]
}

storage_threat_protection = false {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    azure_issue["storage_threat_protection"]
}

storage_threat_protection_err = "Advanced Threat Protection is currently not enabled for storage account" {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    azure_issue["storage_threat_protection"]
}

storage_threat_protection_metadata := {
    "Policy Code": "PR-AZR-ARM-STR-005",
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
# PR-AZR-ARM-STR-006

default blobService = null

azure_attribute_absence["blobService"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    not resource.properties.encryption.services.blob.enabled
}

source_path[{"blobService":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    not resource.properties.encryption.services.blob.enabled
    metadata:= {
        "resource_path": [["resources",i,"properties","encryption","services","blob","enabled"]]
    }
}

azure_issue["blobService"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    resource.properties.encryption.services.blob.enabled != true
}

source_path[{"blobService":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    resource.properties.encryption.services.blob.enabled != true
    metadata:= {
        "resource_path": [["resources",i,"properties","encryption","services","blob","enabled"]]
    }
}

blobService {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    not azure_attribute_absence["blobService"]
    not azure_issue["blobService"]
}

blobService  {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    azure_attribute_absence["blobService"]
    not azure_issue["blobService"]
}

blobService = false {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    azure_issue["blobService"]
}

blobService_err = "Ensure that 'Storage service encryption' is enabled for the Blob Service" {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    azure_issue["blobService"]
}

blobService_metadata := {
    "Policy Code": "PR-AZR-ARM-STR-006",
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
# PR-AZR-ARM-STR-007

default fileService = null

azure_attribute_absence["fileService"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    not resource.properties.encryption.services.file.enabled
}

source_path[{"fileService":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    not resource.properties.encryption.services.file.enabled
    metadata:= {
        "resource_path": [["resources",i,"properties","encryption","services","file","enabled"]]
    }
}

azure_issue["fileService"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    resource.properties.encryption.services.file.enabled != true
}

source_path[{"fileService":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    resource.properties.encryption.services.file.enabled != true
    metadata:= {
        "resource_path": [["resources",i,"properties","encryption","services","file","enabled"]]
    }
}

fileService {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    not azure_attribute_absence["fileService"]
    not azure_issue["fileService"]
}

fileService {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    azure_attribute_absence["fileService"]
    not azure_issue["fileService"]
}

fileService = false {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    azure_issue["fileService"]
}

fileService_err = "Ensure that 'Storage service encryption' is enabled for the File Service" {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    azure_issue["fileService"]
}

fileService_metadata := {
    "Policy Code": "PR-AZR-ARM-STR-007",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure that 'Storage service encryption' is enabled for the File Service",
    "Policy Description": "Azure Storage encryption protects your data and helps you to meet your organizational security and compliance commitments. Data in Azure Storage is encrypted and decrypted transparently using 256-bit AES encryption, one of the strongest block ciphers available, and is FIPS 140-2 compliant. Azure Storage encryption is similar to BitLocker encryption on Windows.",
    "Resource Type": "microsoft.storage/storageaccounts",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts"
}


# https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts
# PR-AZR-ARM-STR-008

default keySource = null

azure_attribute_absence["keySource"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    not resource.properties.encryption.keySource
}

source_path[{"keySource":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    not resource.properties.encryption.keySource
    metadata:= {
        "resource_path": [["resources",i,"properties","encryption","keySource"]]
    }
}

azure_issue["keySource"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    lower(resource.properties.encryption.keySource) != "microsoft.keyvault"
}

source_path[{"keySource":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    lower(resource.properties.encryption.keySource) != "microsoft.keyvault"
    metadata:= {
        "resource_path": [["resources",i,"properties","encryption","keySource"]]
    }
}

keySource {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    not azure_attribute_absence["keySource"]
    not azure_issue["keySource"]
}

keySource = false {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    azure_issue["keySource"]
}

keySource = false {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    azure_attribute_absence["keySource"]
}

keySource_err = "Critical data storage in Storage Account is currently not encrypted with Customer Managed Key" {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    azure_issue["keySource"]
} else = "Storage Account encryption property 'keySource' is missing from the resource" {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    azure_attribute_absence["keySource"]
}

keySource_metadata := {
    "Policy Code": "PR-AZR-ARM-STR-008",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure critical data storage in Storage Account is encrypted with Customer Managed Key",
    "Policy Description": "By default, data in the storage account is encrypted using Microsoft Managed Keys at rest. All Azure Storage resources are encrypted, including blobs, disks, files, queues, and tables. All object metadata is also encrypted. However, if you want to control and manage this encryption key yourself, you can specify a customer-managed key, that key is used to protect and control access to the key that encrypts your data. You can also choose to automatically update the key version used for Azure Storage encryption whenever a new version is available in the associated Key Vault.",
    "Resource Type": "microsoft.storage/storageaccounts",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts"
}


# PR-AZR-ARM-STR-009

default region = null

azure_issue["region"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    not resource.location
}

source_path[{"region":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    not resource.location
    metadata:= {
        "resource_path": [["resources",i,"location"]]
    }
}

azure_issue["region"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    lower(resource.location) != "northeurope"
    lower(resource.location) != "westeurope"
}

source_path[{"region":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    lower(resource.location) != "northeurope"
    lower(resource.location) != "westeurope"
    metadata:= {
        "resource_path": [["resources",i,"location"]]
    }
}

region {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    not azure_issue["region"]
}

region = false {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    azure_issue["region"]
}

region_err = "Storage Accounts location configuration is currenly not inside of Europe" {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    azure_issue["region"]
}

region_metadata := {
    "Policy Code": "PR-AZR-ARM-STR-009",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Storage Accounts location configuration should be inside of Europe",
    "Policy Description": "Identify Storage Accounts outside of the following regions: northeurope, westeurope",
    "Resource Type": "microsoft.storage/storageaccounts",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts"
}


# PR-AZR-ARM-STR-010

default blobServicePublicAccessDisabled = null

azure_attribute_absent["blobServicePublicAccessDisabled"] {
	resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    not resource.properties
}

#default to true. ref: https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts?tabs=json#storageaccountpropertiescreateparameters
azure_attribute_absent["blobServicePublicAccessDisabled"] {
	resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    not has_property(resource.properties, "allowBlobPublicAccess")
}

azure_issue["blobServicePublicAccessDisabled"] {
	resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    resource.properties.allowBlobPublicAccess == true
}

blobServicePublicAccessDisabled {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    not azure_attribute_absent["blobServicePublicAccessDisabled"]
    not azure_issue["blobServicePublicAccessDisabled"]
}

blobServicePublicAccessDisabled = false {
 	resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    azure_attribute_absent["blobServicePublicAccessDisabled"]
}

blobServicePublicAccessDisabled = false {
 	resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    azure_issue["blobServicePublicAccessDisabled"]
}

blobServicePublicAccessDisabled_err = "Storage Account currently allowing public access to all blobs or containers" {
	resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    azure_issue["blobServicePublicAccessDisabled"]
} else = "microsoft.storage/storageaccounts property 'allowBlobPublicAccess' is missing from the resource. Please set the value to false after property addition." {
	resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    azure_attribute_absent["blobServicePublicAccessDisabled"]
}

blobServicePublicAccessDisabled_metadata := {
    "Policy Code": "PR-AZR-ARM-STR-010",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure that Storage Account should not allow public access to all blobs or containers",
    "Policy Description": "This policy will identify which Storage Account has public access enabled for all blobs or containers",
    "Resource Type": "microsoft.storage/storageaccounts",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts"
}


 # PR-AZR-ARM-STR-011

default storage_acount_by_pass = null

azure_attribute_absence["storage_acount_by_pass"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    not resource.properties.networkAcls.bypass
}

source_path[{"storage_acount_by_pass":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    not resource.properties.networkAcls.bypass
    metadata:= {
        "resource_path": [["resources",i,"properties","networkAcls","bypass"]]
    }
}

azure_issue["storage_acount_by_pass"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    lower(resource.properties.networkAcls.bypass) != "azureservices"
}

source_path[{"storage_acount_by_pass":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    lower(resource.properties.networkAcls.bypass) != "azureservices"
    metadata:= {
        "resource_path": [["resources",i,"properties","networkAcls","bypass"]]
    }
}

storage_acount_by_pass {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    not azure_attribute_absence["storage_acount_by_pass"]
    not azure_issue["storage_acount_by_pass"]
}

storage_acount_by_pass = false {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    azure_issue["storage_acount_by_pass"]
}

storage_acount_by_pass = false {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    azure_attribute_absence["storage_acount_by_pass"]
}

storage_acount_by_pass_err = "Azure Storage Account Trusted Microsoft Services access is not enabled" {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    azure_issue["storage_acount_by_pass"]
} else = "microsoft.storage/storageaccounts resource property networkAcls.bypass missing in the resource" {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    azure_attribute_absence["storage_acount_by_pass"]
}

storage_acount_by_pass_metadata := {
    "Policy Code": "PR-AZR-ARM-STR-011",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Storage Account Trusted Microsoft Services access should be enabled",
    "Policy Description": "Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are any combination of Logging, Metrics, AzureServices (For example, 'Logging, Metrics'), or None to bypass none of those traffics. - None, Logging, Metrics, AzureServices.",
    "Resource Type": "microsoft.storage/storageaccounts",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts"
}


# PR-AZR-ARM-STR-018
#

default storage_account_latest_tls_configured = null

#default to TLS1_0
azure_attribute_absence["storage_account_latest_tls_configured"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    not resource.properties.minimumTlsVersion
}

source_path[{"storage_account_latest_tls_configured":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    not resource.properties.minimumTlsVersion
    metadata:= {
        "resource_path": [["resources",i,"properties","minimumTlsVersion"]]
    }
}

azure_issue["storage_account_latest_tls_configured"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    lower(resource.properties.minimumTlsVersion) != "tls1_2"
}

source_path[{"storage_account_latest_tls_configured":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    lower(resource.properties.minimumTlsVersion) != "tls1_2"
    metadata:= {
        "resource_path": [["resources",i,"properties","minimumTlsVersion"]]
    }
}

storage_account_latest_tls_configured {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    not azure_attribute_absence["storage_account_latest_tls_configured"]
    not azure_issue["storage_account_latest_tls_configured"]
}

storage_account_latest_tls_configured = false {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    azure_attribute_absence["storage_account_latest_tls_configured"]
}

storage_account_latest_tls_configured = false {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    azure_issue["storage_account_latest_tls_configured"]
}

storage_account_latest_tls_configured_err = "Azure Storage Account currently dont have latest version of tls configured" {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    azure_issue["storage_account_latest_tls_configured"]
} else = "microsoft.storage/storageaccounts property 'minimumTlsVersion' need to be exist. Its missing from the resource. Please set the value to 'TLS1_2' after property addition." {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    azure_attribute_absence["storage_account_latest_tls_configured"]
}

storage_account_latest_tls_configured_metadata := {
    "Policy Code": "PR-AZR-ARM-STR-018",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure Azure Storage Account has latest version of tls configured",
    "Policy Description": "This policy will identify the Azure Storage Account which don't have the latest version of tls configured and give the alert",
    "Resource Type": "microsoft.storage/storageaccounts",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts"
}

# PR-AZR-ARM-STR-019
#

default storage_account_private_endpoint = null

azure_attribute_absence["storage_account_private_endpoint"] {
    count([c | lower(input.resources[_].type) == "microsoft.network/privateendpoints"; c := 1]) == 0
}

azure_issue ["storage_account_private_endpoint"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    count([c | r := input.resources[_];
              lower(r.type) == "microsoft.network/privateendpoints";
              contains(lower(r.properties.privateLinkServiceConnections[_].properties.privateLinkServiceId), lower(concat("/", [resource.type, resource.name])));
              c := 1]) == 0
}

# no_azure_issue["storage_account_private_endpoint"] {
#     resource := input.resources[_]
#     lower(resource.type) == "microsoft.network/privateendpoints"
#     privateLinkServiceConnection := resource.properties.privateLinkServiceConnections[_]
#     contains(lower(privateLinkServiceConnection.properties.privateLinkServiceId), "microsoft.storage/storageaccounts")
# }

storage_account_private_endpoint {
	resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    not azure_attribute_absence["storage_account_private_endpoint"]
    not azure_issue["storage_account_private_endpoint"]
}

storage_account_private_endpoint = false {
	resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    azure_issue["storage_account_private_endpoint"]
}

storage_account_private_endpoint = false {
	resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    azure_attribute_absence["storage_account_private_endpoint"]
}

storage_account_private_endpoint_err = "Azure Storage Account does not configure with private endpoints" {
	resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    azure_issue["storage_account_private_endpoint"]
} else = "Azure Private endpoints resoruce is missing" {
	resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    azure_attribute_absence["storage_account_private_endpoint"]
}

storage_account_private_endpoint_metadata := {
    "Policy Code": "PR-AZR-ARM-STR-019",
    "Type": "IaC",  
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Storage accounts should use private link",
    "Policy Description": "Azure Private Link lets you connect your virtual network to Azure services without a public IP address at the source or destination. The Private Link platform handles the connectivity between the consumer and services over the Azure backbone network. By mapping private endpoints to your storage account, data leakage risks are reduced. Learn more about private links at - https://aka.ms/azureprivatelinkoverview",
    "Resource Type": "microsoft.storage/storageaccounts",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts"
}


#
# PR-AZR-ARM-STR-020
#

default storage_account_require_encryption = null

azure_attribute_absence["storage_account_require_encryption"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    not resource.properties.encryption.requireInfrastructureEncryption
}

source_path[{"storage_account_require_encryption":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    not resource.properties.encryption.requireInfrastructureEncryption
    metadata:= {
        "resource_path": [["resources",i,"properties","encryption","requireInfrastructureEncryption"]]
    }
}


azure_issue["storage_account_require_encryption"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    resource.properties.encryption.requireInfrastructureEncryption != true
}


source_path[{"storage_account_require_encryption":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    resource.properties.encryption.requireInfrastructureEncryption != true
    metadata:= {
        "resource_path": [["resources",i,"properties","encryption","requireInfrastructureEncryption"]]
    }
}

storage_account_require_encryption {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    not azure_issue["storage_account_require_encryption"]
    not azure_attribute_absence["storage_account_require_encryption"]
}

storage_account_require_encryption = false {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    azure_issue["storage_account_require_encryption"]
}

storage_account_require_encryption = false {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    azure_attribute_absence["storage_account_require_encryption"]
}

storage_account_require_encryption_err = "Storage account encryption scopes currently disabled for double encryption for data at rest" {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    azure_issue["storage_account_require_encryption"]
} else = "microsoft.storage/storageaccounts property 'encryption.requireInfrastructureEncryption' need to be exist. Its missing from the resource. Please set the value to 'true' after property addition." {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    azure_attribute_absence["storage_account_require_encryption"]
}

storage_account_require_encryption_metadata := {
    "Policy Code": "PR-AZR-ARM-STR-020",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Storage accounts should have infrastructure encryption",
    "Policy Description": "Enable infrastructure encryption for higher level of assurance that the data is secure. When infrastructure encryption is enabled, data in a storage account is encrypted twice.",
    "Resource Type": "microsoft.storage/storageaccounts",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts"
}

#
# PR-AZR-ARM-STR-021
#

default storage_account_scopes_require_encryption = null

azure_attribute_absence["storage_account_scopes_require_encryption"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts/encryptionscopes"
    not resource.properties.requireInfrastructureEncryption
}

source_path[{"storage_account_scopes_require_encryption":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.storage/storageaccounts/encryptionscopes"
    not resource.properties.requireInfrastructureEncryption
    metadata:= {
        "resource_path": [["resources",i,"properties","requireInfrastructureEncryption"]]
    }
}

azure_issue["storage_account_scopes_require_encryption"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts/encryptionscopes"
    resource.properties.requireInfrastructureEncryption != true
}

source_path[{"storage_account_scopes_require_encryption":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.storage/storageaccounts/encryptionscopes"
    resource.properties.requireInfrastructureEncryption != true
    metadata:= {
        "resource_path": [["resources",i,"properties","requireInfrastructureEncryption"]]
    }
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
    "Policy Code": "PR-AZR-ARM-STR-021",
    "Type": "IaC",  
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Storage account encryption scopes should have infrastructure encryption",
    "Policy Description": "Enable infrastructure encryption for encryption at the rest of your storage account encryption scopes for added security. Infrastructure encryption ensures that your data is encrypted twice.",
    "Resource Type": "microsoft.storage/storageaccounts/encryptionscopes",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts/encryptionscopes"
}

# PR-AZR-ARM-STR-022
#

default storage_account_encryption_scopes_source = null

azure_attribute_absence["storage_account_encryption_scopes_source"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts/encryptionscopes"
    not resource.properties.source
}

source_path[{"storage_account_encryption_scopes_source":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.storage/storageaccounts/encryptionscopes"
    not resource.properties.source
    metadata:= {
        "resource_path": [["resources",i,"properties","source"]]
    }
}

azure_issue["storage_account_encryption_scopes_source"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts/encryptionscopes"
    lower(resource.properties.source) != "microsoft.keyvault"
}

source_path[{"storage_account_encryption_scopes_source":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.storage/storageaccounts/encryptionscopes"
    lower(resource.properties.source) != "microsoft.keyvault"
    metadata:= {
        "resource_path": [["resources",i,"properties","source"]]
    }
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
    "Policy Code": "PR-AZR-ARM-STR-022",
    "Type": "IaC",  
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Storage account encryption scopes should use customer-managed keys to encrypt data at rest",
    "Policy Description": "Use customer-managed keys to manage the encryption at the rest of your storage account encryption scopes. Customer-managed keys enable the data to be encrypted with an Azure key-vault key created and owned by you. You have full control and responsibility for the key lifecycle, including rotation and management. Learn more about storage account encryption scopes at https://aka.ms/encryption-scopes-overview.",
    "Resource Type": "microsoft.storage/storageaccounts/encryptionscopes",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts/encryptionscopes"
}

#
# PR-AZR-ARM-STR-023
#

default storage_vnet_service_endpoint = null

azure_attribute_absence["storage_vnet_service_endpoint"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    not resource.properties.networkAcls.defaultAction
}

source_path[{"storage_vnet_service_endpoint":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    not resource.properties.networkAcls.defaultAction
    metadata:= {
        "resource_path": [["resources",i,"properties","networkAcls","defaultAction"]]
    }
}

azure_attribute_absence["storage_vnet_service_endpoint"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    not resource.properties.networkAcls.virtualNetworkRules
}

source_path[{"storage_vnet_service_endpoint":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    not resource.properties.networkAcls.virtualNetworkRules
    metadata:= {
        "resource_path": [["resources",i,"properties","networkAcls","virtualNetworkRules"]]
    }
}

azure_issue["storage_vnet_service_endpoint"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    lower(resource.properties.networkAcls.defaultAction) != "deny"
}

source_path[{"storage_vnet_service_endpoint":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    lower(resource.properties.networkAcls.defaultAction) != "deny"
    metadata:= {
        "resource_path": [["resources",i,"properties","networkAcls","defaultAction"]]
    }
}


azure_issue["storage_vnet_service_endpoint"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    virtualNetworkRule := resource.properties.networkAcls.virtualNetworkRules[_]
    count(virtualNetworkRule.id) == 0
}

source_path[{"storage_vnet_service_endpoint":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    virtualNetworkRule := resource.properties.networkAcls.virtualNetworkRules[j]
    count(virtualNetworkRule.id) == 0
    metadata:= {
        "resource_path": [["resources",i,"properties","networkAcls","virtualNetworkRules",j,"id"]]
    }
}

storage_vnet_service_endpoint {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    not azure_attribute_absence["storage_vnet_service_endpoint"]
    not azure_issue["storage_vnet_service_endpoint"]
}

storage_vnet_service_endpoint = false {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    azure_issue["storage_vnet_service_endpoint"]
}

storage_vnet_service_endpoint = false {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    azure_attribute_absence["storage_vnet_service_endpoint"]
}

storage_vnet_service_endpoint_err = "Storage Accounts firewall rule is currently not enabled" {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    azure_issue["storage_vnet_service_endpoint"]
} else = "Storage Account attribute networkAcls.defaultAction or networkAcls.virtualNetworkRules.id is missing from the resource" {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    azure_attribute_absence["storage_vnet_service_endpoint"]
}

storage_vnet_service_endpoint_metadata := {
    "Policy Code": "PR-AZR-ARM-STR-023",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Storage Accounts should use a virtual network service endpoint",
    "Policy Description": "This policy audits any Storage Account not configured to use a virtual network service endpoint.",
    "Resource Type": "microsoft.storage/storageaccounts",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts"
}


#
# PR-AZR-ARM-STR-024
#

default storage_account_allow_shared_key_access = null

azure_attribute_absence["storage_account_allow_shared_key_access"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    not has_property(resource.properties,"allowSharedKeyAccess")
}

azure_issue["storage_account_allow_shared_key_access"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    resource.properties.allowSharedKeyAccess != false
}

storage_account_allow_shared_key_access {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    not azure_issue["storage_account_allow_shared_key_access"]
    not azure_attribute_absence["storage_account_allow_shared_key_access"]
}

storage_account_allow_shared_key_access = false {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    azure_issue["storage_account_allow_shared_key_access"]
}

storage_account_allow_shared_key_access = false {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    azure_attribute_absence["storage_account_allow_shared_key_access"]
}

storage_account_allow_shared_key_access_err = "Storage accounts currently use shared key access" {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    azure_issue["storage_account_allow_shared_key_access"]
} else = "microsoft.storage/storageaccounts property 'allowSharedKeyAccess' need to be exist. Its missing from the resource. Please set the value to 'false' after property addition." {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not storage_account_need_to_skip(resource)
    azure_attribute_absence["storage_account_allow_shared_key_access"]
}

storage_account_allow_shared_key_access_metadata := {
    "Policy Code": "PR-AZR-ARM-STR-024",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Storage accounts should prevent shared key access",
    "Policy Description": "Audit requirement of Azure Active Directory (Azure AD) to authorize requests for your storage account. By default, requests can be authorized with either Azure Active Directory credentials or by using the account access key for Shared Key authorization. Of these two types of authorization, Azure AD provides superior security and ease of use over Shared Key and is recommended by Microsoft.",
    "Resource Type": "microsoft.storage/storageaccounts",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts"
}


#
# PR-AZR-ARM-STR-025
#

default storage_account_file_share_usage_smb_protocol = null

azure_attribute_absence["storage_account_file_share_usage_smb_protocol"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts/fileservices/shares"
    not has_property(resource.properties, "enabledProtocols")
}

azure_issue["storage_account_file_share_usage_smb_protocol"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts/fileservices/shares"
    lower(resource.properties.enabledProtocols) != "smb"
}

storage_account_file_share_usage_smb_protocol {
    lower(input.resources[_].type) == "microsoft.storage/storageaccounts/fileservices/shares"
    not azure_attribute_absence["storage_account_file_share_usage_smb_protocol"]
    not azure_issue["storage_account_file_share_usage_smb_protocol"]
}

storage_account_file_share_usage_smb_protocol = false {
    azure_issue["storage_account_file_share_usage_smb_protocol"]
}

storage_account_file_share_usage_smb_protocol {
    azure_attribute_absence["storage_account_file_share_usage_smb_protocol"]
    not azure_issue["storage_account_file_share_usage_smb_protocol"]
}

storage_account_file_share_usage_smb_protocol_err = "Storage accounts File Share currently not using SMB protocol" {
    azure_issue["storage_account_file_share_usage_smb_protocol"]
}

storage_account_file_share_usage_smb_protocol_metadata := {
    "Policy Code": "PR-AZR-ARM-STR-025",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Storage Account File Share should use SMB protocol",
    "Policy Description": "The Server Message Block (SMB) protocol is a network file sharing protocol that allows applications on a computer to read and write to files and to request services from server programs in a computer network. The SMB protocol can be used on top of its TCP/IP protocol or other network protocols.",
    "Resource Type": "Microsoft.Storage/storageAccounts/fileServices/shares",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts/fileservices/shares?tabs=json"
}