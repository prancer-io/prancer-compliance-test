package rule

# https://docs.microsoft.com/en-us/azure/templates/azurerm_key_vault_secret

#
# PR-AZR-0018-TRF
#

default kv_expire = null

azure_attribute_absence["kv_expire"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_key_vault_secret"
    not resource.properties.expiration_date
}

azure_issue["kv_expire"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_key_vault_secret"
    count(resource.properties.expiration_date) = 0
}

kv_expire {
    lower(input.resources[_].type) == "azurerm_key_vault_secret"
    not azure_issue["kv_expire"]
    not azure_attribute_absence["kv_expire"]
}

kv_expire = false {
    azure_issue["kv_expire"]
}

kv_expire = false {
    azure_attribute_absence["kv_expire"]
}

kv_expire_err = "Azure Key Vault secrets have no expiration date" {
    azure_issue["kv_expire"]
}

kv_expire_miss_err = "Azure Key Vault attribute expiration_date missing in the resource" {
    azure_attribute_absence["kv_expire"]
}

kv_expire_metadata := {
    "Policy Code": "PR-AZR-0018-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Key Vault secrets have no expiration date",
    "Policy Description": "PR-AZR-0018-TRF-DESC",
    "Compliance": [],
    "Resource Type": "azurerm_key_vault_secret",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/azurerm_key_vault_secret"
}
