package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts/blobservices

#
# PR-AZR-CLD-STR-001
#
# SideNote for Reference: This cannot be done via Terraform. terraform can only change retention days.
# See the note section at https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account#container_delete_retention_policy
# Note is applicable for delete_retention_policy as well.
default storage_blob_soft_delete = null

azure_attribute_absence["storage_blob_soft_delete"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts/blobservices"
    not resource.properties.deleteRetentionPolicy.enabled
}

azure_issue["storage_blob_soft_delete"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts/blobservices"
    resource.properties.deleteRetentionPolicy.enabled != true
}

storage_blob_soft_delete {
    lower(input.resources[_].type) == "microsoft.storage/storageaccounts/blobservices"
    not azure_attribute_absence["storage_blob_soft_delete"]
    not azure_issue["storage_blob_soft_delete"]
}

storage_blob_soft_delete = false {
    azure_attribute_absence["storage_blob_soft_delete"]
}

storage_blob_soft_delete = false {
    azure_issue["storage_blob_soft_delete"]
}

storage_blob_soft_delete_err = "microsoft.storage/storageaccounts/blobservices resource property deleteRetentionPolicy.enabled is missing." {
    azure_attribute_absence["storage_blob_soft_delete"]
} else = "Soft delete on blob service should be enabled" {
    azure_issue["storage_blob_soft_delete"]
}

storage_blob_soft_delete_metadata := {
    "Policy Code": "PR-AZR-CLD-STR-001",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Soft delete on blob service should be enabled",
    "Policy Description": "The blob service properties for blob soft delete. It helps to restore removed blob within configured retention days",
    "Resource Type": "microsoft.storage/storageaccounts/blobservices",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts/blobservices"
}


#
# PR-AZR-CLD-STR-002
#
# SideNote for Reference: This cannot be done via Terraform. terraform can only change retention days.
# See the note section at https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account#container_delete_retention_policy
default storage_blob_container_soft_delete = null

azure_attribute_absence["storage_blob_container_soft_delete"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts/blobservices"
    not resource.properties.containerDeleteRetentionPolicy.enabled
}

azure_issue["storage_blob_container_soft_delete"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts/blobservices"
    resource.properties.containerDeleteRetentionPolicy.enabled != true
}

storage_blob_container_soft_delete {
    lower(input.resources[_].type) == "microsoft.storage/storageaccounts/blobservices"
    not azure_attribute_absence["storage_blob_container_soft_delete"]
    not azure_issue["storage_blob_container_soft_delete"]
}

storage_blob_container_soft_delete = false {
    azure_attribute_absence["storage_blob_container_soft_delete"]
}


storage_blob_container_soft_delete = false {
    azure_issue["storage_blob_container_soft_delete"]
}

storage_blob_container_soft_delete_err = "microsoft.storage/storageaccounts/blobservices resource property containerDeleteRetentionPolicy.enabled is missing." {
    azure_attribute_absence["storage_blob_container_soft_delete"]
} else = "Soft delete on blob service container should be enabled" {
    azure_issue["storage_blob_container_soft_delete"]
}

storage_blob_container_soft_delete_metadata := {
    "Policy Code": "PR-AZR-CLD-STR-002",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Soft delete on blob service container should be enabled",
    "Policy Description": "The blob service properties for container soft delete. It helps to restore removed blob containers within configured retention days.",
    "Resource Type": "microsoft.storage/storageaccounts/blobservices",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts/blobservices"
}
