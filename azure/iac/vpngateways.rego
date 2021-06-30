package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.network/vpngateways

#
# PR-AZR-0098-ARM
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

vpn_encrypt_metadata := {
    "Policy Code": "PR-AZR-0098-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "VPN is not configured with cryptographic algorithm",
    "Policy Description": "Azure VPN gateways to use a custom IPsec/IKE policy with specific cryptographic algorithms and key strengths, rather than the Azure default policy sets. IPsec and IKE protocol standard supports a wide range of cryptographic algorithms in various combinations. If customers do not request a specific combination of cryptographic algorithms and parameters, Azure VPN gateways use a set of default proposals. Typically due to compliance or security requirements, you can now configure your Azure VPN gateways to use a custom IPsec/IKE policy with specific cryptographic algorithms and key strengths, rather than the Azure default policy sets. It is thus recommended to use custom policy sets and choose strong cryptography.",
    "Resource Type": "microsoft.network/vpngateways",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/vpngateways"
}
