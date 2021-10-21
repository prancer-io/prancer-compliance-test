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

metadata := {
    "Policy Code": "PR-AZR-0074",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "Cloud",
    "Policy Title": "Azure storage accounts has blob container(s) with public access",
    "Policy Description": "'Public access level' allows you to grant anonymous/public read access to a container and the blobs within Azure blob storage. By doing so, you can grant read-only access to these resources without sharing your account key, and without requiring a shared access signature.<br><br>This policy identifies blob containers within an Azure storage account that allow anonymous/public access ('CONTAINER' or 'BLOB'). As a best practice, do not allow anonymous/public access to blob containers unless you have a very good reason. Instead, you should consider using a shared access signature token for providing controlled and time-limited access to blob containers.",
    "Resource Type": "microsoft.storage/storageaccounts/blobservices/containers",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/2019-06-01/storageaccounts/blobservices/containers"
}
