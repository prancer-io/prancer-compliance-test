package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts/blobservices

#
# PR-AZR-0126-ARM
#

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


storage_blob_soft_delete_miss_err = "Soft delete on blob service is not exists" {
    azure_attribute_absence["storage_blob_soft_delete"]
}

storage_blob_soft_delete_err = "Soft delete on blob service is not enabled" {
    azure_issue["storage_blob_soft_delete"]
}

storage_blob_soft_delete_metadata := {
    "Policy Code": "PR-AZR-0126-ARM",
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
# PR-AZR-0127-ARM
#

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

storage_blob_container_soft_delete_miss_err = "Soft delete on blob service container is not exists" {
    azure_attribute_absence["storage_blob_container_soft_delete"]
}

storage_blob_container_soft_delete_err = "Soft delete on blob service container is not enabled" {
    azure_issue["storage_blob_container_soft_delete"]
}

storage_blob_container_soft_delete_metadata := {
    "Policy Code": "PR-AZR-0127-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Soft delete on blob service container should be enabled",
    "Policy Description": "The blob service properties for container soft delete. It helps to restore removed blob containers within configured retention days.",
    "Resource Type": "microsoft.storage/storageaccounts/blobservices",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts/blobservices"
}
