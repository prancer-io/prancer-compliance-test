package rule

# https://docs.microsoft.com/en-us/azure/templates/azurerm_key_vault_secret
# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault_secret
#
# PR-AZR-0018-TRF
#

default kv_expire = null

azure_issue["kv_expire"] {
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
    not azure_issue["kv_expire"]
}

kv_expire = false {
    azure_issue["kv_expire"]
}

kv_expire_err = "Azure Key Vault secrets does not have any expiration date" {
    azure_issue["kv_expire"]
}

kv_expire_metadata := {
    "Policy Code": "PR-AZR-0018-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Key Vault secrets should have expiration date",
    "Policy Description": "PR-AZR-0018-TRF-DESC",
    "Resource Type": "azurerm_key_vault_secret",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault_secret"
}
