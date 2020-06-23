package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.network/vpngateways

#
# VPN is not configured with cryptographic algorithm (307)
#

default vpn_encrypt = null

vpn_encrypt {
    lower(input.type) == "microsoft.network/vpngateways"
    count([ c | 
        lower(input.properties.connections[i].properties.ipsecPolicies[i].ipsecEncryption) == "none";
        c := 1]) == 0
}

vpn_encrypt = false {
    lower(input.type) == "microsoft.network/vpngateways"
    lower(input.properties.connections[_].properties.ipsecPolicies[_].ipsecEncryption) == "none"
}

vpn_encrypt_err = "Azure virtual network peer is disconnected" {
    vpn_encrypt == false
}
