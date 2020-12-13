package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/2019-06-01/storageaccounts/blobservices/containers

#
# PR-AZR-0074-TRF
# PR-AZR-0013-TRF
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
