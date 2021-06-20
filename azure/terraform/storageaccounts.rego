package rule

# https://docs.microsoft.com/en-us/azure/templates/azurerm_storage_account

#
# PR-AZR-0092-TRF
#

default storage_secure = null

azure_issue["storage_secure"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_storage_account"
    resource.properties.enable_https_traffic_only != true
}

storage_secure {
    lower(input.resources[_].type) == "azurerm_storage_account"
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

storage_secure_metadata := {
    "Policy Code": "PR-AZR-0092-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Storage Accounts without Secure transfer enabled",
    "Policy Description": "The secure transfer option enhances the security of your storage account by only allowing requests to the storage account by a secure connection. For example, when calling REST APIs to access your storage accounts, you must connect using HTTPs. Any requests using HTTP will be rejected when 'secure transfer required' is enabled. When you are using the Azure files service, connection without encryption will fail, including scenarios using SMB 2.1, SMB 3.0 without encryption, and some flavors of the Linux SMB client. Because Azure storage doesnâ€™t support HTTPs for custom domain names, this option is not applied when using a custom domain name.",
    "Resource Type": "azurerm_storage_account_network_rules",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/azurerm_storage_account"
}

#
# PR-AZR-0093-TRF
#

default storage_acl = null

azure_attribute_absence["storage_acl"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_storage_account_network_rules"
    not resource.properties.default_action
}

azure_issue["storage_acl"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_storage_account_network_rules"
    lower(resource.properties.default_action) != "deny"
}

storage_acl {
    lower(input.resources[_].type) == "azurerm_storage_account_network_rules"
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

storage_acl_err = "Storage Account attribute default_action missing in the resource" {
    azure_attribute_absence["storage_acl"]
}

storage_acl_metadata := {
    "Policy Code": "PR-AZR-0093-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Storage Accounts without their firewalls enabled (TJX)",
    "Policy Description": "Turning on firewall rules for your storage account blocks incoming requests for data by default, unless the requests come from a service that is operating within an Azure Virtual Network (VNet). Requests that are blocked include those from other Azure services, from the Azure portal, from logging and metrics services, and so on._x005F_x000D_ _x005F_x000D_ You can grant access to Azure services that operate from within a VNet by allowing the subnet of the service instance. Enable a limited number of scenarios through the Exceptions mechanism described in the following section. To access the Azure portal, you would need to be on a machine within the trusted boundary (either IP or VNet) that you set up.",
    "Resource Type": "azurerm_storage_account_network_rules",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/azurerm_storage_account"
}
