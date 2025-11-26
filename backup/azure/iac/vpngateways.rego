package rule

array_contains(target_array, element) = true {
  lower(target_array[_]) == lower(element)
} else = false { true }

# https://docs.microsoft.com/en-us/azure/templates/microsoft.network/vpngateways

#
# PR-AZR-ARM-NET-006
#

default vpn_encrypt = null

azure_attribute_absence["vpn_encrypt"] {
    count([c | lower(input.resources[_].type) == "microsoft.network/vpngateways/vpnconnections"; c := 1]) == 0
}

azure_attribute_absence["vpn_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/vpngateways/vpnconnections"
    not resource.dependsOn
}

azure_attribute_absence["vpn_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/vpngateways/vpnconnections"
    not resource.ipsecPolicies
}

azure_issue["vpn_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/vpngateways"
    count([c | r := input.resources[_];
              lower(r.type) == "microsoft.network/vpngateways/vpnconnections";
              array_contains(r.dependsOn, concat("/", [resource.type, resource.name]));
              lower(r.properties.ipsecPolicies[_].ipsecEncryption) != "none";
              c := 1]) == 0
}

azure_inner_attribute_absence["vpn_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/vpngateways"
    not resource.properties.connections
}

azure_inner_attribute_absence["vpn_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/vpngateways"
    con := resource.properties.connections[_]
    not con.properties.ipsecPolicies
}

azure_inner_attribute_absence["vpn_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/vpngateways"
    con := resource.properties.connections[_]
    ipsec := con.properties.ipsecPolicies[_]
    not ipsec.ipsecEncryption
}

azure_inner_issue["vpn_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/vpngateways"
    con := resource.properties.connections[_]
    ipsec := con.properties.ipsecPolicies[_]
    lower(ipsec.ipsecEncryption) == "none"
}

vpn_encrypt {
    lower(input.resources[_].type) == "microsoft.network/vpngateways"
    not azure_attribute_absence["vpn_encrypt"]
    not azure_issue["vpn_encrypt"]
}

vpn_encrypt {
    lower(input.resources[_].type) == "microsoft.network/vpngateways"
    not azure_inner_attribute_absence["vpn_encrypt"]
    not azure_inner_issue["vpn_encrypt"]
}

vpn_encrypt = false {
    lower(input.resources[_].type) == "microsoft.network/vpngateways"
    azure_attribute_absence["vpn_encrypt"]
    azure_inner_attribute_absence["vpn_encrypt"]
}

vpn_encrypt = false {
    lower(input.resources[_].type) == "microsoft.network/vpngateways"
    azure_issue["vpn_encrypt"]
    azure_inner_issue["vpn_encrypt"]
}

vpn_encrypt = false {
    lower(input.resources[_].type) == "microsoft.network/vpngateways"
    azure_inner_attribute_absence["vpn_encrypt"]
    azure_issue["vpn_encrypt"]
}

vpn_encrypt = false {
    lower(input.resources[_].type) == "microsoft.network/vpngateways"
    azure_attribute_absence["vpn_encrypt"]
    azure_inner_issue["vpn_encrypt"]
}

vpn_encrypt_err = "VPN gateways is currently not configured with cryptographic algorithm" {
    lower(input.resources[_].type) == "microsoft.network/vpngateways"
    azure_issue["vpn_encrypt"]
    azure_inner_issue["vpn_encrypt"]
} else = "VPN gateways connections or ipsec policies property 'ipsecEncryption' is missing from the resource" {
    lower(input.resources[_].type) == "microsoft.network/vpngateways"
    azure_attribute_absence["vpn_encrypt"]
    azure_inner_attribute_absence["vpn_encrypt"]
} else = "VPN gateways connections or ipsec policies property 'ipsecEncryption' is missing from the resource" {
    lower(input.resources[_].type) == "microsoft.network/vpngateways"
    azure_inner_attribute_absence["vpn_encrypt"]
    azure_issue["vpn_encrypt"]
} else = "VPN gateways connections or ipsec policies property 'ipsecEncryption' is missing from the resource" {
    lower(input.resources[_].type) == "microsoft.network/vpngateways"
    azure_attribute_absence["vpn_encrypt"]
    azure_inner_issue["vpn_encrypt"]
}

vpn_encrypt_metadata := {
    "Policy Code": "PR-AZR-ARM-NET-006",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure VPN gateways is configured with cryptographic algorithm",
    "Policy Description": "Azure VPN gateways to use a custom IPsec/IKE policy with specific cryptographic algorithms and key strengths, rather than the Azure default policy sets. IPsec and IKE protocol standard supports a wide range of cryptographic algorithms in various combinations. If customers do not request a specific combination of cryptographic algorithms and parameters, Azure VPN gateways use a set of default proposals. Typically due to compliance or security requirements, you can now configure your Azure VPN gateways to use a custom IPsec/IKE policy with specific cryptographic algorithms and key strengths, rather than the Azure default policy sets. It is thus recommended to use custom policy sets and choose strong cryptography.",
    "Resource Type": "microsoft.network/vpngateways",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/vpngateways"
}
