package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts/blobservices/blobservices

#
# Soft delete on Blob not enabled
#

default storage_blob_soft_delete = null

azure_issue["storage_blob_soft_delete"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts/blobservices"
    resource.properties.deleteRetentionPolicy.enabled != true
}

azure_issue["storage_blob_soft_delete"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts/blobservices"
    resource.properties.containerDeleteRetentionPolicy.enabled != true
}

storage_blob_soft_delete {
    lower(input.resources[_].type) == "microsoft.storage/storageaccounts/blobservices"
    not azure_issue["storage_blob_soft_delete"]
}

storage_blob_soft_delete = false {
    azure_issue["storage_blob_soft_delete"]
}

storage_blob_soft_delete_err = "Soft delete on Blob not enabled" {
    azure_issue["storage_blob_soft_delete"]
}
