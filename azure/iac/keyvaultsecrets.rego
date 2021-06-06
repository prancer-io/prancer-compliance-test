package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.keyvault/vaults/secrets

#
# PR-AZR-0018-ARM
#

default kv_expire = null

azure_attribute_absence["kv_expire"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.keyvault/vaults/secrets"
    resource.properties.attributes.enabled != false
    not resource.properties.attributes.exp
}

azure_issue["kv_expire"] {
    resource := input.resources[_]
    resource.properties.attributes.enabled != false
    to_number(resource.properties.attributes.exp) < 0
}

kv_expire {
    lower(input.resources[_].type) == "microsoft.keyvault/vaults/secrets"
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

kv_expire_miss_err = "Azure Key Vault attribute exp missing in the resource" {
    azure_attribute_absence["kv_expire"]
}

kv_expire_metadata := {
    "Policy Code": "PR-AZR-0018-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "AWS Cloud formation",
    "Policy Title": "Azure Key Vault secrets have no expiration date",
    "Policy Description": "PR-AZR-0018-ARM-DESC",
    "Resource Type": "microsoft.keyvault/vaults/secrets",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.keyvault/vaults/secrets"
}
