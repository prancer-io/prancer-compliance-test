package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts

#
# Storage Accounts without Secure transfer enabled (301)
#

default storage_secure = null

storage_secure {
    lower(input.type) == "microsoft.storage/storageaccounts"
    input.properties.supportsHttpsTrafficOnly == true
}

storage_secure = false {
    lower(input.type) == "microsoft.storage/storageaccounts"
    input.properties.supportsHttpsTrafficOnly == false
}

storage_secure_err = "Storage Accounts without Secure transfer enabled" {
    storage_secure == false
}

#
# Storage Accounts without their firewalls enabled (302)
#

storage_acl {
    lower(input.type) == "microsoft.storage/storageaccounts"
    lower(input.properties.networkAcls.defaultAction) == "deny"
}

storage_acl = false {
    lower(input.type) == "microsoft.storage/storageaccounts"
    lower(input.properties.networkAcls.defaultAction) != "deny"
}

storage_acl_err = "Storage Accounts without their firewalls enabled" {
    storage_acl == false
}
