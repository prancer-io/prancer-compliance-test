package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/2019-06-01/storageaccounts/blobservices/containers

#
# Azure storage accounts has blob containers with public access (283)
# Azure Blob container(s) with public access and logging set to less than 180 days (222)
#

default storage_public_access = null

storage_public_access {
    lower(input.type) == "microsoft.storage/storageaccounts/blobservices/containers"
    lower(input.properties.publicAccess) == "none"
}

storage_public_access = false {
    lower(input.type) == "microsoft.storage/storageaccounts/blobservices/containers"
    lower(input.properties.publicAccess) == "container"
}

storage_public_access = false {
    lower(input.type) == "microsoft.storage/storageaccounts/blobservices/containers"
    lower(input.properties.publicAccess) == "blob"
}

storage_public_access_err = "Azure storage accounts has blob containers with public access" {
    storage_public_access == false
}
