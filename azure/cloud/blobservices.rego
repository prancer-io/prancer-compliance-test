package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts/blobservices

#
# PR-AZR-STR-001

default storage_blob_soft_delete = null

azure_attribute_absence["storage_blob_soft_delete"] {
    not input.properties.deleteRetentionPolicy.enabled
}

azure_issue["storage_blob_soft_delete"] {
    input.properties.deleteRetentionPolicy.enabled != true
}

storage_blob_soft_delete {
    not azure_attribute_absence["storage_blob_soft_delete"]
    not azure_issue["storage_blob_soft_delete"]
}

storage_blob_soft_delete = false {
    azure_attribute_absence["storage_blob_soft_delete"]
}

storage_blob_soft_delete = false {
    azure_issue["storage_blob_soft_delete"]
}

storage_blob_soft_delete_err = "Soft delete on blob service should be enabled" {
    azure_attribute_absence["storage_blob_soft_delete"]
} else = "microsoft.storage/storageaccounts/blobservices resource property deleteRetentionPolicy.enabled is missing." {
    azure_issue["storage_blob_soft_delete"]
}

storage_blob_soft_delete_metadata := {
    "Policy Code": "PR-AZR-STR-001",
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
# PR-AZR-STR-002
#
default storage_blob_container_soft_delete = null

azure_attribute_absence["storage_blob_container_soft_delete"] {
    not input.properties.containerDeleteRetentionPolicy.enabled
}

azure_issue["storage_blob_container_soft_delete"] {
    input.properties.containerDeleteRetentionPolicy.enabled != true
}

storage_blob_container_soft_delete {
    not azure_attribute_absence["storage_blob_container_soft_delete"]
    not azure_issue["storage_blob_container_soft_delete"]
}

storage_blob_container_soft_delete = false {
    azure_attribute_absence["storage_blob_container_soft_delete"]
}


storage_blob_container_soft_delete = false {
    azure_issue["storage_blob_container_soft_delete"]
}

storage_blob_container_soft_delete_err = "Soft delete on blob service container should be enabled" {
    azure_issue["storage_blob_container_soft_delete"]
} else = "microsoft.storage/storageaccounts/blobservices resource property containerDeleteRetentionPolicy.enabled is missing." {
    azure_attribute_absence["storage_blob_container_soft_delete"]
}

storage_blob_container_soft_delete_metadata := {
    "Policy Code": "PR-AZR-STR-002",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Soft delete on blob service container should be enabled",
    "Policy Description": "The blob service properties for container soft delete. It helps to restore removed blob containers within configured retention days.",
    "Resource Type": "microsoft.storage/storageaccounts/blobservices",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts/blobservices"
}
