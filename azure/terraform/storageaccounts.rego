package rule

# https://docs.microsoft.com/en-us/azure/templates/azurerm_storage_account
# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account
#
# PR-AZR-0092-TRF
#

default storage_secure = null

azure_attribute_absence["storage_secure"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_storage_account"
    # Defaults to true if property not available
    not resource.properties.enable_https_traffic_only
}

azure_issue["storage_secure"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_storage_account"
    resource.properties.enable_https_traffic_only != true
}

storage_secure {
    lower(input.resources[_].type) == "azurerm_storage_account"
    not azure_attribute_absence["storage_secure"]
    not azure_issue["storage_secure"]
}

storage_secure {
    azure_attribute_absence["storage_secure"]
}

storage_secure = false {
    azure_issue["storage_secure"]
}

storage_secure_err = "Storage Accounts https based secure transfer is not enabled" {
    azure_issue["storage_secure"]
}

storage_secure_metadata := {
    "Policy Code": "PR-AZR-0092-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Storage Accounts https based secure transfer should be enabled",
    "Policy Description": "The secure transfer option enhances the security of your storage account by only allowing requests to the storage account by a secure connection. For example, when calling REST APIs to access your storage accounts, you must connect using HTTPs. Any requests using HTTP will be rejected when 'secure transfer required' is enabled. When you are using the Azure files service, connection without encryption will fail, including scenarios using SMB 2.1, SMB 3.0 without encryption, and some flavors of the Linux SMB client. Because Azure storage doesnâ€™t support HTTPs for custom domain names, this option is not applied when using a custom domain name.",
    "Resource Type": "azurerm_storage_account",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account"
}


#
# PR-AZR-0093-TRF
# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account_network_rules

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
    not azure_attribute_absence["storage_acl"]
    not azure_issue["storage_acl"]
}

storage_acl = false {
    azure_attribute_absence["storage_acl"]
}

storage_acl = false {
    azure_issue["storage_acl"]
}


storage_acl_err = "azurerm_storage_account_network_rules property 'default_action' need to be exist. Its missing from the resource. Please set the value to 'deny' after property addition." {
    azure_attribute_absence["storage_acl"]
} else = "Storage Accounts firewall rule is currently not enabled" {
    azure_issue["storage_acl"]
}

storage_acl_metadata := {
    "Policy Code": "PR-AZR-0093-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Storage Accounts should have firewall rules enabled",
    "Policy Description": "Turning on firewall rules for your storage account blocks incoming requests for data by default, unless the requests come from a service that is operating within an Azure Virtual Network (VNet). Requests that are blocked include those from other Azure services, from the Azure portal, from logging and metrics services, and so on._x005F_x000D_ _x005F_x000D_ You can grant access to Azure services that operate from within a VNet by allowing the subnet of the service instance. Enable a limited number of scenarios through the Exceptions mechanism described in the following section. To access the Azure portal, you would need to be on a machine within the trusted boundary (either IP or VNet) that you set up.",
    "Resource Type": "azurerm_storage_account_network_rules",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account_network_rules"
}

#
# PR-AZR-0123-TRF

default storage_account_public_access_disabled = null

# defaults to false
azure_attribute_absence["storage_account_public_access_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_storage_account"
    not resource.properties.allow_blob_public_access
}

azure_issue["storage_account_public_access_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_storage_account"
    resource.properties.allow_blob_public_access == true
}

storage_account_public_access_disabled {
    lower(input.resources[_].type) == "azurerm_storage_account"
    not azure_attribute_absence["storage_account_public_access_disabled"]
    not azure_issue["storage_account_public_access_disabled"]
}

storage_account_public_access_disabled {
    azure_attribute_absence["storage_account_public_access_disabled"]
}

storage_account_public_access_disabled = false {
    azure_issue["storage_account_public_access_disabled"]
}

storage_account_public_access_disabled_err = "Storage Account currently allowing public access to all blobs or containers" {
    azure_issue["storage_secure"]
}

storage_account_public_access_disabled_metadata := {
    "Policy Code": "PR-AZR-0123-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure that Storage Account should not allow public access to all blobs or containers",
    "Policy Description": "This policy will identify which Storage Account has public access not disabled for all blobs or containers and alert",
    "Resource Type": "azurerm_storage_account",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account"
}
