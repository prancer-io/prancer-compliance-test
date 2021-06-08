#
# PR-AZR-0018
#

package rule
default rulepass = false

# https://docs.microsoft.com/en-us/azure/templates/microsoft.keyvault/vaults/secrets

rulepass {
    lower(input.type) == "microsoft.keyvault/vaults/secrets"
    to_number(input.properties.attributes.exp) > 0
}

metadata := {
    "Policy Code": "PR-AZR-0018",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "Cloud",
    "Policy Title": "Azure Key Vault secrets have no expiration date",
    "Policy Description": "PR-AZR-0018-DESC",
    "Compliance": [],
    "Resource Type": "microsoft.keyvault/vaults/secrets",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.keyvault/vaults/secrets"
}
