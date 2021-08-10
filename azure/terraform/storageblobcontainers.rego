package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/2019-06-01/storageaccounts/blobservices/containers
# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_container
#
# PR-AZR-0074-TRF
#

default storage_container_public_access_disabled = null

# Defaults to private
azure_attribute_absence["storage_container_public_access_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_storage_container"
    not resource.properties.container_access_type
}

azure_issue["storage_container_public_access_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_storage_container"
    lower(resource.properties.container_access_type) != "private"
}

storage_container_public_access_disabled {
    lower(input.resources[_].type) == "azurerm_storage_container"
    not azure_attribute_absence["storage_container_public_access_disabled"]
    not azure_issue["storage_container_public_access_disabled"]
}

storage_container_public_access_disabled {
    azure_attribute_absence["storage_container_public_access_disabled"]
}

storage_container_public_access_disabled = false {
    azure_issue["storage_container_public_access_disabled"]
}

storage_container_public_access_disabled_err = "Azure storage accounts has blob containers with public access" {
    azure_issue["storage_container_public_access_disabled"]
}

storage_container_public_access_disabled_metadata := {
    "Policy Code": "PR-AZR-0074-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure storage blob container should not have public access enabled",
    "Policy Description": "'Public access level' allows you to grant anonymous/public read access to a container and the blobs within Azure blob storage. By doing so, you can grant read-only access to these resources without sharing your account key, and without requiring a shared access signature._x005F_x000D_ _x005F_x000D_ This policy identifies blob containers within an Azure storage account that allow anonymous/public access ('CONTAINER' or 'BLOB'). As a best practice, do not allow anonymous/public access to blob containers unless you have a very good reason. Instead, you should consider using a shared access signature token for providing controlled and time-limited access to blob containers.",
    "Resource Type": "azurerm_storage_account",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_container"
}
