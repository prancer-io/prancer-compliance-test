#
# PR-AZR-0098
#

package rule

default rulepass = true

# https://docs.microsoft.com/en-us/azure/templates/microsoft.network/vpngateways

rulepass = false {
    lower(input.type) == "microsoft.network/vpngateways"
    lower(input.properties.connections[_].properties.ipsecPolicies[_].ipsecEncryption) == "none"
}
