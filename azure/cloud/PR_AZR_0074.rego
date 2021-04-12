#
# PR-AZR-0074
#

package rule
default rulepass = true

# https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/2019-06-01/storageaccounts/blobservices/containers

rulepass = false {
    lower(input.type) == "microsoft.storage/storageaccounts/blobservices/containers"
    input.properties.publicAccess == "Container"
}

rulepass = false {
    lower(input.type) == "microsoft.storage/storageaccounts/blobservices/containers"
    input.properties.publicAccess == "Blob"
}
