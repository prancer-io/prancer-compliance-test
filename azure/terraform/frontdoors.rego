package rule

# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/frontdoor
# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/frontdoor_firewall_policy
#
# PR-AZR-TRF-FRD-001
#

default frontdoors_has_drs_configured = null

has_any_defaultruleset(managed_rule) = true {
  managed_rule_found := managed_rule[_]
  contains(lower(managed_rule_found.type), "defaultruleset")
  to_number(managed_rule_found.version) >= 1
} else = false { true }


azure_attribute_absence["frontdoors_has_drs_configured"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_frontdoor"
    not resource.properties.frontend_endpoint
}

azure_attribute_absence["frontdoors_has_drs_configured"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_frontdoor"
    frontend_endpoint := resource.properties.frontend_endpoint[_]
    not frontendEndpoints.web_application_firewall_policy_link_id
}

azure_attribute_absence ["frontdoors_has_drs_configured"] {
    count([c | lower(input.resources[_].type) == "azurerm_frontdoor_firewall_policy"; c := 1]) == 0
}

# Note: We cant check the dependency between microsoft.network/frontdoors and microsoft.network/frontdoorwebapplicationfirewallpolicies 
# based on association of id from microsoft.network/frontdoorwebapplicationfirewallpolicies to microsoft.network/frontdoors resources properties.frontendEndpoints[_].properties.webApplicationFirewallPolicyLink.id
# due to snapshot variable parsing limitation. but the rule is designed such a way so that it will failed on each invalid scenario.
# Managed Default Rule Set: 
#- Microsoft_DefaultRuleSet_1.1 (944240 Remote Command Execution: Java serialization (CVE-2015-5842))
#- DefaultRuleSet_1.0 (944240 Remote Command Execution: Java serialization (CVE-2015-5842))
#- DefaultRuleSet_perview-0.1 (944240 Java: possible payload execution) 
# Dont check for DefaultRuleSet_perview-0.1. rule 944240 is not updated yet with "Remote Command Execution". add this to the rego rule when updated with "Remote Command Execution"
azure_issue["frontdoors_has_drs_configured"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_frontdoor"
    count([c | r := input.resources[_];
              r.type == "azurerm_frontdoor_firewall_policy";
              contains(resource.properties.frontend_endpoint[_].web_application_firewall_policy_link_id, r.properties.compiletime_identity);
              has_any_defaultruleset(r.properties.managed_rule);
              c := 1]) == 0
    count([c | r := input.resources[_];
              r.type == "azurerm_frontdoor_firewall_policy";
              contains(resource.properties.frontend_endpoint[_].web_application_firewall_policy_link_id, concat(".", [r.type, r.name]));
              has_any_defaultruleset(r.properties.managed_rule);
              c := 1]) == 0
}

frontdoors_has_drs_configured {
    lower(input.resources[_].type) == "azurerm_frontdoor"
    not azure_attribute_absence["frontdoors_has_drs_configured"]
    not azure_issue["frontdoors_has_drs_configured"]
}

frontdoors_has_drs_configured = false {
    lower(input.resources[_].type) == "azurerm_frontdoor"
    azure_issue["frontdoors_has_drs_configured"]
}

frontdoors_has_drs_configured = false {
    lower(input.resources[_].type) == "azurerm_frontdoor"
    azure_attribute_absence["frontdoors_has_drs_configured"]
}

frontdoors_has_drs_configured_err = "'azurerm_frontdoor' resource's 'frontend_endpoint' or its property 'web_application_firewall_policy_link_id' is missing or misconfigured with 'azurerm_frontdoor_firewall_policy'" {
    lower(input.resources[_].type) == "azurerm_frontdoor"
    azure_attribute_absence["frontdoors_has_drs_configured"]
} else = "Azure frontDoors currently not configured with WAF policy with Default Rule Set 1.0/1.1" {
    lower(input.resources[_].type) == "azurerm_frontdoor"
    azure_issue["frontdoors_has_drs_configured"]
}

frontdoors_has_drs_configured_metadata := {
    "Policy Code": "PR-AZR-TRF-FRD-001",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure frontDoors should have configured with WAF policy with Default Rule Set 1.0/1.1 for proactive protection against CVE-2021-44228 exploit",
    "Policy Description": "It is recommended to enable WAF policy with Default Rule Set 1.0/1.1 on Front Door deployments to immediately avail of additional protection from log4j Remote Command Execution. details at https://www.microsoft.com/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-2-exploitation/",
    "Resource Type": "azurerm_frontdoor",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/frontdoor"
}