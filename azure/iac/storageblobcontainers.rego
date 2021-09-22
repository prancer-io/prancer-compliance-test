package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/2019-06-01/storageaccounts/blobservices/containers

#
# PR-AZR-0074-ARM
#

default storage_container_public_access_disabled = null
#https://docs.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-configure?tabs=portal
azure_attribute_absence["storage_container_public_access_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts/blobservices/containers"
    not resource.properties.publicAccess
}

azure_issue["storage_container_public_access_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts/blobservices/containers"
    lower(resource.properties.publicAccess) == "container"
}

azure_issue["storage_container_public_access_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts/blobservices/containers"
    lower(resource.properties.publicAccess) == "blob"
}

storage_container_public_access_disabled {
    lower(input.resources[_].type) == "microsoft.storage/storageaccounts/blobservices/containers"
    not azure_attribute_absence["storage_container_public_access_disabled"]
    not azure_issue["storage_container_public_access_disabled"]
}

storage_container_public_access_disabled = false {
    azure_issue["storage_public_access_disabled"]
}

storage_container_public_access_disabled = false {
    azure_attribute_absence["storage_public_access_disabled"]
}

storage_container_public_access_disabled_err = "Azure storage account currently allowing public access to the blob container" {
    azure_issue["storage_public_access_disabled"]
} else = "Azure storage account blob service property 'publicAccess' is missing from the resource"  {
    azure_attribute_absence["storage_public_access_disabled"]
}

storage_container_public_access_disabled_metadata := {
    "Policy Code": "PR-AZR-0074-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure storage blob container should not have public access enabled",
    "Policy Description": "'Public access level' allows you to grant anonymous/public read access to a container and the blobs within Azure blob storage. By doing so, you can grant read-only access to these resources without sharing your account key, and without requiring a shared access signature._x005F_x000D_ _x005F_x000D_ This policy identifies blob containers within an Azure storage account that allow anonymous/public access ('CONTAINER' or 'BLOB'). As a best practice, do not allow anonymous/public access to blob containers unless you have a very good reason. Instead, you should consider using a shared access signature token for providing controlled and time-limited access to blob containers.",
    "Resource Type": "microsoft.storage/storageaccounts/blobservices/containers",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/2019-06-01/storageaccounts/blobservices/containers"
}



# PR-AZR-0073-ARM
#

default storage__logical_container_public_access_disabled = null

azure_attribute_absence["storage__logical_container_public_access_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    storage_resources := resource.resources[_]
    lower(storage_resources.type) == "blobservices/containers"
    not storage_resources.properties.publicAccess
}

azure_issue["storage__logical_container_public_access_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    storage_resources := resource.resources[_]
    lower(storage_resources.type) == "blobservices/containers"
    lower(storage_resources.properties.publicAccess) == "container"
}

azure_issue["storage__logical_container_public_access_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    storage_resources := resource.resources[_]
    lower(storage_resources.type) == "blobservices/containers"
    lower(storage_resources.properties.publicAccess) == "blob"
}

storage__logical_container_public_access_disabled {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    storage_resources := resource.resources[_]
    lower(storage_resources.type) == "blobservices/containers"
    not azure_attribute_absence["storage__logical_container_public_access_disabled"]
    not azure_issue["storage__logical_container_public_access_disabled"]
}

storage__logical_container_public_access_disabled = false {
    azure_issue["storage__logical_container_public_access_disabled"]
}

storage__logical_container_public_access_disabled = false {
    azure_attribute_absence["storage__logical_container_public_access_disabled"]
}

storage__logical_container_public_access_disabled_err = "Azure storage account currently allowing public access to the blob container" {
    azure_issue["storage__logical_container_public_access_disabled"]
} else = "Azure storage account blob service property 'publicAccess' is missing from the resource"  {
    azure_attribute_absence["storage__logical_container_public_access_disabled"]
}

storage__logical_container_public_access_disabled_metadata := {
    "Policy Code": "PR-AZR-0073-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure storage blob container should not have public access enabled",
    "Policy Description": "'Public access level' allows you to grant anonymous/public read access to a container and the blobs within Azure blob storage. By doing so, you can grant read-only access to these resources without sharing your account key, and without requiring a shared access signature._x005F_x000D_ _x005F_x000D_ This policy identifies blob containers within an Azure storage account that allow anonymous/public access ('CONTAINER' or 'BLOB'). As a best practice, do not allow anonymous/public access to blob containers unless you have a very good reason. Instead, you should consider using a shared access signature token for providing controlled and time-limited access to blob containers.",
    "Resource Type": "microsoft.storage/storageaccounts/blobservices/containers",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/2019-06-01/storageaccounts/blobservices/containers"
}
