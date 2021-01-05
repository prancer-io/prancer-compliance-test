package rule

# https://docs.microsoft.com/en-us/azure/templates/azurerm_storage_account

#
# PR-AZR-0092-TRF
#

default storage_secure = null

azure_issue["storage_secure"] {
    resource := input.json.resources[_]
    lower(resource.type) == "azurerm_storage_account"
    resource.properties.enable_https_traffic_only != true
}

storage_secure {
    lower(input.json.resources[_].type) == "azurerm_storage_account"
    not azure_issue["storage_secure"]
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

#
# PR-AZR-0093-TRF
#

default storage_acl = null

azure_attribute_absence["storage_acl"] {
    resource := input.json.resources[_]
    lower(resource.type) == "azurerm_storage_account_network_rules"
    not resource.properties.default_action
}

azure_issue["storage_acl"] {
    resource := input.json.resources[_]
    lower(resource.type) == "azurerm_storage_account_network_rules"
    lower(resource.properties.default_action) != "deny"
}

storage_acl {
    lower(input.json.resources[_].type) == "azurerm_storage_account_network_rules"
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

storage_acl_miss_err = "Storage Account attribute default_action missing in the resource" {
    azure_attribute_absence["storage_acl"]
}
