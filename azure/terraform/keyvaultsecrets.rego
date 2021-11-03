package rule

# https://docs.microsoft.com/en-us/azure/templates/azurerm_key_vault_secret
# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault_secret
#
# PR-AZR-TRF-KV-005
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
    not regex.match("^[2-9]\\d{3}-(0[1-9]|1[012])-(0[1-9]|[12][0-9]|3[01]).*",
        resource.properties.expiration_date)
}

kv_expire {
    lower(input.resources[_].type) == "azurerm_key_vault_secret"
    not azure_attribute_absence["kv_expire"]
    not azure_issue["kv_expire"]
}

kv_expire = false {
    azure_attribute_absence["kv_expire"]
}

kv_expire = false {
    azure_issue["kv_expire"]
}

kv_expire_err = "azurerm_key_vault_secret property 'expiration_date' need to be exist. Its missing from the resource." {
    azure_attribute_absence["kv_expire"]
} else = "Azure Key Vault secrets does not have any expiration date" {
    azure_issue["kv_expire"]
}

kv_expire_metadata := {
    "Policy Code": "PR-AZR-TRF-KV-005",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Key Vault secrets should have an expiration date",
    "Policy Description": "This policy identifies Azure Key Vault secrets that do not have an expiration date. As a best practice, set an expiration date for each secret and rotate the secret regularly.",
    "Resource Type": "azurerm_key_vault_secret",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault_secret"
}
