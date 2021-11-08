package rule

# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault_key
#
# PR-AZR-TRF-KV-004
#

default kv_keys_expire = null

azure_attribute_absence["kv_keys_expire"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_key_vault_key"
    not resource.properties.expiration_date
}

azure_issue["kv_keys_expire"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_key_vault_key"
    not regex.match("^[2-9]\\d{3}-(0[1-9]|1[012])-(0[1-9]|[12][0-9]|3[01]).*",
        resource.properties.expiration_date)
}

kv_keys_expire {
    lower(input.resources[_].type) == "azurerm_key_vault_key"
    not azure_attribute_absence["kv_keys_expire"]
    not azure_issue["kv_keys_expire"]
}

kv_keys_expire = false {
    azure_attribute_absence["kv_keys_expire"]
}

kv_keys_expire = false {
    azure_issue["kv_keys_expire"]
}

kv_keys_expire_err = "azurerm_key_vault_key property 'expiration_date' need to be exist. Its missing from the resource." {
    azure_attribute_absence["kv_keys_expire"]
} else = "Azure Key Vault key does not have any expiration date" {
    azure_issue["kv_keys_expire"]
}

kv_keys_expire_metadata := {
    "Policy Code": "PR-AZR-TRF-KV-004",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Key Vault keys should have an expiration date",
    "Policy Description": "This policy identifies Azure Key Vault keys that do not have an expiration date. As a best practice, set an expiration date for each key.",
    "Resource Type": "azurerm_key_vault_key",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault_key"
}
