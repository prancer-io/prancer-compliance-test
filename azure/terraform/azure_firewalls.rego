package rule

# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/firewall
# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/firewall_policy
#
# PR-AZR-TRF-AFW-001
#

default azure_firewall_configured_with_idpc_and_tls_inspection = null

azure_attribute_absence["azure_firewall_configured_with_idpc_and_tls_inspection"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_firewall"
    not resource.properties.sku_tier
}

azure_attribute_absence["azure_firewall_configured_with_idpc_and_tls_inspection"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_firewall"
    not resource.properties.firewall_policy_id
}

azure_attribute_absence["azure_firewall_configured_with_idpc_and_tls_inspection"] {
    count([c | lower(input.resources[_].type) == "azurerm_firewall_policy"; c := 1]) == 0
}

azure_issue["azure_firewall_configured_with_idpc_and_tls_inspection"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_firewall"
    lower(resource.properties.sku_tier) != "premium"
}

azure_issue["azure_firewall_configured_with_idpc_and_tls_inspection"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_firewall"
    count([c | r := input.resources[_];
              r.type == "azurerm_firewall_policy";
              contains(resource.properties.firewall_policy_id, r.properties.compiletime_identity);
              lower(r.properties.sku) == "premium";
              lower(r.properties.intrusion_detection[_].mode) == "deny";
              count(r.properties.tls_certificate[_].key_vault_secret_id) > 0;
              c := 1]) == 0
    count([c | r := input.resources[_];
              r.type == "azurerm_firewall_policy";
              contains(resource.properties.firewall_policy_id, concat(".", [r.type, r.name]));
              lower(r.properties.sku) == "premium";
              lower(r.properties.intrusion_detection[_].mode) == "deny";
              count(r.properties.tls_certificate[_].key_vault_secret_id) > 0;
              c := 1]) == 0
}

azure_firewall_configured_with_idpc_and_tls_inspection {
    lower(input.resources[_].type) == "azurerm_firewall"
    not azure_attribute_absence["azure_firewall_configured_with_idpc_and_tls_inspection"]
    not azure_issue["azure_firewall_configured_with_idpc_and_tls_inspection"]
}

azure_firewall_configured_with_idpc_and_tls_inspection = false {
    lower(input.resources[_].type) == "azurerm_firewall"
    azure_issue["azure_firewall_configured_with_idpc_and_tls_inspection"]
}

azure_firewall_configured_with_idpc_and_tls_inspection = false {
    lower(input.resources[_].type) == "azurerm_firewall"
    azure_attribute_absence["azure_firewall_configured_with_idpc_and_tls_inspection"]
}

azure_firewall_configured_with_idpc_and_tls_inspection_err = "Azure Firewall Premium currently not configured with both IDPS Alert & Deny mode and TLS inspection enabled" {
    lower(input.resources[_].type) == "azurerm_firewall"
    azure_issue["azure_firewall_configured_with_idpc_and_tls_inspection"]
} else = "'azurerm_firewall' resource property 'sku_tier' need to be exist and 'firewall_policy_id' should have id reference of 'azurerm_firewall_policy' resource. Also 'sku' property and 'intrusion_detection' and 'tls_certificate' block need to be exist under 'azurerm_firewall_policy' resource as well. one or all are missing." {
    lower(input.resources[_].type) == "azurerm_firewall"
    azure_attribute_absence["azure_firewall_configured_with_idpc_and_tls_inspection"]
}

azure_firewall_configured_with_idpc_and_tls_inspection_metadata := {
    "Policy Code": "PR-AZR-TRF-AFW-001",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Firewall Premium should be configured with both IDPS Alert & Deny mode and TLS inspection enabled for proactive protection against CVE-2021-44228 exploit",
    "Policy Description": "Azure Firewall Premium has enhanced protection from the Log4j RCE CVE-2021-44228 vulnerability and exploit. Azure Firewall premium IDPS (Intrusion Detection and Prevention System) provides IDPS inspection for all east-west traffic and outbound traffic to internet. details at https://www.microsoft.com/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-2-exploitation/",
    "Resource Type": "azurerm_firewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/firewall"
}