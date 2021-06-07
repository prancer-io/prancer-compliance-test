package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/2019-06-01/storageaccounts/blobservices/containers

#
# PR-AZR-0074-TRF
# PR-AZR-0013-TRF
#

default storage_public_access = null

azure_issue["storage_public_access"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_storage_account"
    resource.properties.allow_blob_public_access
}

storage_public_access {
    lower(input.resources[_].type) == "azurerm_storage_account"
    not azure_issue["storage_public_access"]
}

storage_public_access = false {
    azure_issue["storage_public_access"]
}

storage_public_access_err = "Azure storage accounts has blob containers with public access" {
    azure_issue["storage_public_access"]
}

storage_public_access_metadata := {
    "Policy Code": "PR-AZR-0074-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure storage accounts has blob container(s) with public access",
    "Policy Description": "'Public access level' allows you to grant anonymous/public read access to a container and the blobs within Azure blob storage. By doing so, you can grant read-only access to these resources without sharing your account key, and without requiring a shared access signature._x005F_x000D_ _x005F_x000D_ This policy identifies blob containers within an Azure storage account that allow anonymous/public access ('CONTAINER' or 'BLOB'). As a best practice, do not allow anonymous/public access to blob containers unless you have a very good reason. Instead, you should consider using a shared access signature token for providing controlled and time-limited access to blob containers.",
    "Resource Type": "azurerm_storage_account",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/2019-06-01/storageaccounts/blobservices/containers"
}
