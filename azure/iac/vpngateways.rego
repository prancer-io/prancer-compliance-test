package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.network/vpngateways

#
# VPN is not configured with cryptographic algorithm (307)
#

default vpn_encrypt = null

azure_attribute_absence["vpn_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/vpngateways"
    count([c | con := resource.properties.connections[_];
               ipsec := con.properties.ipsecPolicies[_]
               ipsec.ipsecEncryption; c := 1]) == 0
}

azure_issue["vpn_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/vpngateways"
    lower(resource.properties.connections[_].properties.ipsecPolicies[_].ipsecEncryption) == "none"
}

vpn_encrypt {
    lower(input.resources[_].type) == "microsoft.network/vpngateways"
    not azure_issue["vpn_encrypt"]
    not azure_attribute_absence["vpn_encrypt"]
}

vpn_encrypt = false {
    azure_issue["vpn_encrypt"]
}

vpn_encrypt = false {
    azure_attribute_absence["vpn_encrypt"]
}

vpn_encrypt_err = "VPN is not configured with cryptographic algorithm" {
    azure_issue["vpn_encrypt"]
}

vpn_encrypt_miss_err = "VPN connections or ipsec policies attributes are missing in the resource" {
    azure_attribute_absence["vpn_encrypt"]
}
