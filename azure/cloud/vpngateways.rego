package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.network/vpngateways

#
# PR-AZR-NET-006
#

default vpn_encrypt = null

azure_attribute_absence["vpn_encrypt"] {
    not input.properties.connections
}

azure_attribute_absence["vpn_encrypt"] {
    con := input.properties.connections[_]
    not con.properties.ipsecPolicies
}

azure_attribute_absence["vpn_encrypt"] {
    con := input.properties.connections[_]
    ipsec := con.properties.ipsecPolicies[_]
    not ipsec.ipsecEncryption
}

azure_issue["vpn_encrypt"] {
    con := input.properties.connections[_]
    ipsec := con.properties.ipsecPolicies[_]
    lower(ipsec.ipsecEncryption) == "none"
}

vpn_encrypt {
    not azure_attribute_absence["vpn_encrypt"]
    not azure_issue["vpn_encrypt"]
}

vpn_encrypt = false {
    azure_issue["vpn_encrypt"]
}

vpn_encrypt = false {
    azure_attribute_absence["vpn_encrypt"]
}

vpn_encrypt_err = "VPN gateways is currently not configured with cryptographic algorithm" {
    azure_issue["vpn_encrypt"]
} else = "VPN gateways connections or ipsec policies property 'ipsecEncryption' is missing from the resource" {
    azure_attribute_absence["vpn_encrypt"]
}

vpn_encrypt_metadata := {
    "Policy Code": "PR-AZR-NET-006",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Ensure VPN gateways is configured with cryptographic algorithm",
    "Policy Description": "Azure VPN gateways to use a custom IPsec/IKE policy with specific cryptographic algorithms and key strengths, rather than the Azure default policy sets. IPsec and IKE protocol standard supports a wide range of cryptographic algorithms in various combinations. If customers do not request a specific combination of cryptographic algorithms and parameters, Azure VPN gateways use a set of default proposals. Typically due to compliance or security requirements, you can now configure your Azure VPN gateways to use a custom IPsec/IKE policy with specific cryptographic algorithms and key strengths, rather than the Azure default policy sets. It is thus recommended to use custom policy sets and choose strong cryptography.",
    "Resource Type": "microsoft.network/vpngateways",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/vpngateways"
}
