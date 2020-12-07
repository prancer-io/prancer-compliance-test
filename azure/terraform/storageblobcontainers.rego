package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/2019-06-01/storageaccounts/blobservices/containers

#
# Azure storage accounts has blob containers with public access (283)
# Azure Blob container(s) with public access and logging set to less than 180 days (222)
#

default storage_public_access = null

azure_issue["storage_public_access"] {
    resource := input.json.resources[_]
    lower(resource.type) == "azurerm_storage_account"
    resource.properties.allow_blob_public_access
}

storage_public_access {
    lower(input.json.resources[_].type) == "azurerm_storage_account"
    not azure_issue["storage_public_access"]
}

storage_public_access = false {
    azure_issue["storage_public_access"]
}

storage_public_access_err = "Azure storage accounts has blob containers with public access" {
    azure_issue["storage_public_access"]
}
