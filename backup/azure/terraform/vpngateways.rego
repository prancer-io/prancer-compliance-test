package rule

# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/virtual_network_gateway_connection

#
# PR-AZR-TRF-NET-006
#

default vpn_encrypt = null
# default to false
# if use_policy_based_traffic_selectors is set to true then ipsec_policy block is required.

azure_attribute_absence["vpn_encrypt"] {
    count([c | input.resources[_].type == "azurerm_virtual_network_gateway_connection"; c := 1]) == 0
}

azure_attribute_absence["vpn_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_virtual_network_gateway_connection"
    not resource.properties.use_policy_based_traffic_selectors 
}

azure_attribute_absence["vpn_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_virtual_network_gateway_connection"
    not resource.properties.ipsec_policy
}

azure_issue["vpn_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_virtual_network_gateway"
    count([c | r := input.resources[_];
              r.type == "azurerm_virtual_network_gateway_connection";
              contains(r.properties.virtual_network_gateway_id, resource.properties.compiletime_identity);
              r.properties.use_policy_based_traffic_selectors == true;
              lower(r.properties.ipsec_policy[_].ipsec_encryption) != "none";
              c := 1]) == 0
    count([c | r := input.resources[_];
              r.type == "azurerm_virtual_network_gateway_connection";
              contains(r.properties.virtual_network_gateway_id, concat(".", [resource.type, resource.name]));
              r.properties.use_policy_based_traffic_selectors == true;
              lower(r.properties.ipsec_policy[_].ipsec_encryption) != "none";
              c := 1]) == 0
}

# azure_issue["vpn_encrypt"] {
#     resource := input.resources[_]
#     lower(resource.type) == "azurerm_virtual_network_gateway_connection"
#     resource.properties.use_policy_based_traffic_selectors == false
# }

# azure_issue["vpn_encrypt"] {
#     resource := input.resources[_]
#     lower(resource.type) == "azurerm_virtual_network_gateway_connection"
#     ipsec_policy := resource.properties.ipsec_policy[_]
#     lower(ipsec_policy.ipsec_encryption) == "none"
# }

vpn_encrypt {
    lower(input.resources[_].type) == "azurerm_virtual_network_gateway"
    not azure_attribute_absence["vpn_encrypt"]
    not azure_issue["vpn_encrypt"]
}

vpn_encrypt = false {
    lower(input.resources[_].type) == "azurerm_virtual_network_gateway"
    azure_issue["vpn_encrypt"]
}

vpn_encrypt = false {
    lower(input.resources[_].type) == "azurerm_virtual_network_gateway"
    azure_attribute_absence["vpn_encrypt"]
}

vpn_encrypt_err = "Resource azurerm_virtual_network_gateway and azurerm_virtual_network_gateway_connection need to be exist and property 'use_policy_based_traffic_selectors' and 'ipsec_policy' block need to be exist under azurerm_virtual_network_gateway_connection as well. one or all are missing from the resource." {
    lower(input.resources[_].type) == "azurerm_virtual_network_gateway"
    azure_attribute_absence["vpn_encrypt"]
} else = "VPN gateways is currently not configured with cryptographic algorithm" {
    lower(input.resources[_].type) == "azurerm_virtual_network_gateway"
    azure_issue["vpn_encrypt"]
}

vpn_encrypt_metadata := {
    "Policy Code": "PR-AZR-TRF-NET-006",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure VPN gateways is configured with cryptographic algorithm",
    "Policy Description": "Azure VPN gateways to use a custom IPsec/IKE policy with specific cryptographic algorithms and key strengths, rather than the Azure default policy sets. IPsec and IKE protocol standard supports a wide range of cryptographic algorithms in various combinations. If customers do not request a specific combination of cryptographic algorithms and parameters, Azure VPN gateways use a set of default proposals. Typically due to compliance or security requirements, you can now configure your Azure VPN gateways to use a custom IPsec/IKE policy with specific cryptographic algorithms and key strengths, rather than the Azure default policy sets. It is thus recommended to use custom policy sets and choose strong cryptography.",
    "Resource Type": "azurerm_virtual_network_gateway",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/virtual_network_gateway_connection"
}
