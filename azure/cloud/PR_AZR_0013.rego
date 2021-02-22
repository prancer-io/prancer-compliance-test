#
# PR-AZR-0013
#

package rule
default rulepass = true

# https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/2019-06-01/storageaccounts/blobservices/containers

rulepass = false {
   input.type == "Microsoft.Storage/storageAccounts/blobServices/containers"
   input.properties.publicAccess == "Container"
}
