package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.network/vpngateways

#
# VPN is not configured with cryptographic algorithm (307)
#

default vpn_encrypt = null

azure_issue["vpn_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/vpngateways"
    lower(resource.properties.connections[_].properties.ipsecPolicies[_].ipsecEncryption) == "none"
}

vpn_encrypt {
    lower(input.resources[_].type) == "microsoft.network/vpngateways"
    not azure_issue["vpn_encrypt"]
}

vpn_encrypt = false {
    azure_issue["vpn_encrypt"]
}

vpn_encrypt_err = "VPN is not configured with cryptographic algorithm" {
    azure_issue["vpn_encrypt"]
}
