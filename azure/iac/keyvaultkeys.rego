package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.keyvault/vaults/keys

#
# PR-AZR-0123-ARM
#

default kv_expire_keys = null

azure_attribute_absence["kv_expire_keys"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.keyvault/vaults/keys"
    resource.properties.attributes.enabled != false
    not resource.properties.attributes.exp
}

azure_issue["kv_expire_keys"] {
    resource := input.resources[_]
    resource.properties.attributes.enabled != false
    to_number(resource.properties.attributes.exp) < 0
}

kv_expire_keys {
    lower(input.resources[_].type) == "microsoft.keyvault/vaults/keys"
    not azure_issue["kv_expire_keys"]
    not azure_attribute_absence["kv_expire_keys"]
}

kv_expire_keys = false {
    azure_issue["kv_expire_keys"]
}

kv_expire_keys = false {
    azure_attribute_absence["kv_expire_keys"]
}

kv_expire_keys_err = "Azure Key Vault keys have no expiration date" {
    azure_issue["kv_expire_keys"]
}

kv_expire_keys_miss_err = "Azure Key Vault attribute exp missing in the resource" {
    azure_attribute_absence["kv_expire_keys"]
}

kv_expire_keys_metadata := {
    "Policy Code": "PR-AZR-0123-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Key Vault keys have no expiration date",
    "Policy Description": "PR-AZR-0018-ARM-DESC",
    "Resource Type": "microsoft.keyvault/vaults/keys",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.keyvault/vaults/keys"
}
