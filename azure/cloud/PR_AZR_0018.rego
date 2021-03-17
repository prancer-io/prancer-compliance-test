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
