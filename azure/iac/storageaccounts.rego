package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts

#
# Storage Accounts without Secure transfer enabled (301)
#

default storage_secure = null

azure_attribute_absence["storage_secure"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not resource.properties.supportsHttpsTrafficOnly
}

azure_issue["storage_secure"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    resource.properties.supportsHttpsTrafficOnly == false
}

storage_secure {
    lower(input.resources[_].type) == "microsoft.storage/storageaccounts"
    not azure_issue["storage_secure"]
    not azure_attribute_absence["storage_secure"]
}

storage_secure = false {
    azure_issue["storage_secure"]
}

storage_secure = false {
    azure_attribute_absence["storage_secure"]
}

storage_secure_err = "Storage Accounts without Secure transfer enabled" {
    azure_issue["storage_secure"]
}

storage_secure_miss_err = "Storage Account attribute supportsHttpsTrafficOnly missing in the resource" {
    azure_attribute_absence["storage_secure"]
}

#
# Storage Accounts without their firewalls enabled (302)
#

default storage_acl = null

azure_attribute_absence["storage_acl"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not resource.properties.networkAcls.defaultAction
}

azure_issue["storage_acl"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    lower(resource.properties.networkAcls.defaultAction) != "deny"
}

storage_acl {
    lower(input.resources[_].type) == "microsoft.storage/storageaccounts"
    not azure_issue["storage_acl"]
    not azure_attribute_absence["storage_acl"]
}

storage_acl = false {
    azure_issue["storage_acl"]
}

storage_acl = false {
    azure_attribute_absence["storage_acl"]
}

storage_acl_err = "Storage Accounts without their firewalls enabled" {
    azure_issue["storage_acl"]
}

storage_acl_miss_err = "Storage Account attribute networkAcls.defaultAction missing in the resource" {
    azure_attribute_absence["storage_acl"]
}
