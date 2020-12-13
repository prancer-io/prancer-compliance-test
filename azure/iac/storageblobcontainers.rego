package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/2019-06-01/storageaccounts/blobservices/containers

#
# PR-AZR-0074-ARM
# PR-AZR-0013-ARM
#

default storage_public_access = null

azure_attribute_absence["storage_public_access"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts/blobservices/containers"
    not resource.properties.publicAccess
}

azure_issue["storage_public_access"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts/blobservices/containers"
    lower(resource.properties.publicAccess) == "container"
}

azure_issue["storage_public_access"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts/blobservices/containers"
    lower(resource.properties.publicAccess) == "blob"
}

storage_public_access {
    lower(input.resources[_].type) == "microsoft.storage/storageaccounts/blobservices/containers"
    not azure_issue["storage_public_access"]
    not azure_attribute_absence["storage_public_access"]
}

storage_public_access = false {
    azure_issue["storage_public_access"]
}

storage_public_access = false {
    azure_attribute_absence["storage_public_access"]
}

storage_public_access_err = "Azure storage accounts has blob containers with public access" {
    azure_issue["storage_public_access"]
}

storage_public_access_err = "Storage account attribute publicAccess missing in the resource" {
    azure_attribute_absence["storage_public_access"]
}
