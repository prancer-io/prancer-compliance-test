package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.network/frontdoorwebapplicationfirewallpolicies?tabs=json
# https://docs.microsoft.com/en-us/azure/templates/microsoft.network/frontdoors?tabs=json
#
# PR-AZR-CLD-FRD-001
#

default frontdoors_has_drs_configured = null

has_any_defaultruleset(managedRuleSets) = true {
  each_managedRuleSets := managedRuleSets[_]
  contains(lower(each_managedRuleSets.ruleSetType), "defaultruleset")
  to_number(each_managedRuleSets.ruleSetVersion) >= 1
} else = false { true }


azure_attribute_absence["frontdoors_has_drs_configured"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/frontdoors"
    not resource.properties.frontendEndpoints
}

azure_attribute_absence["frontdoors_has_drs_configured"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/frontdoors"
    frontendEndpoints := resource.properties.frontendEndpoints[_]
    not frontendEndpoints.properties.webApplicationFirewallPolicyLink.id
}

azure_issue["frontdoors_has_drs_configured"] {
     resource := input.resources[_]
     lower(resource.type) == "microsoft.network/frontdoors"
     frontendEndpoints := resource.properties.frontendEndpoints[_]
     count(frontendEndpoints.properties.webApplicationFirewallPolicyLink.id) == 0
}

azure_attribute_absence ["frontdoors_has_drs_configured"] {
    count([c | lower(input.resources[_].type) == "microsoft.network/frontdoorwebapplicationfirewallpolicies"; c := 1]) == 0
}

azure_attribute_absence["frontdoors_has_drs_configured"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/frontdoorwebapplicationfirewallpolicies"
    not resource.properties.managedRules
}

azure_attribute_absence["frontdoors_has_drs_configured"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/frontdoorwebapplicationfirewallpolicies"
    not resource.properties.managedRules.managedRuleSets
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
     lower(resource.type) == "microsoft.network/frontdoorwebapplicationfirewallpolicies"
     not has_any_defaultruleset(resource.properties.managedRules.managedRuleSets)
}

frontdoors_has_drs_configured {
    lower(input.resources[_].type) == "microsoft.network/frontdoors"
    not azure_attribute_absence["frontdoors_has_drs_configured"]
    not azure_issue["frontdoors_has_drs_configured"]
}

frontdoors_has_drs_configured = false {
    lower(input.resources[_].type) == "microsoft.network/frontdoors"
    azure_issue["frontdoors_has_drs_configured"]
}

frontdoors_has_drs_configured = false {
    lower(input.resources[_].type) == "microsoft.network/frontdoors"
    azure_attribute_absence["frontdoors_has_drs_configured"]
}

frontdoors_has_drs_configured_err = "'microsoft.network/frontdoors' resource's 'frontendEndpoints' or its property block 'webApplicationFirewallPolicyLink' is missing or misconfigured with 'microsoft.network/frontdoorwebapplicationfirewallpolicies'" {
    lower(input.resources[_].type) == "microsoft.network/frontdoors"
    azure_attribute_absence["frontdoors_has_drs_configured"]
} else = "Azure frontDoors currently not configured with WAF policy with Default Rule Set 1.0/1.1" {
    lower(input.resources[_].type) == "microsoft.network/frontdoors"
    azure_issue["frontdoors_has_drs_configured"]
}

frontdoors_has_drs_configured_metadata := {
    "Policy Code": "PR-AZR-CLD-FRD-001",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure frontDoors should have configured with WAF policy with Default Rule Set 1.0/1.1 for proactive protection against CVE-2021-44228 exploit",
    "Policy Description": "It is recommended to enable WAF policy with Default Rule Set 1.0/1.1 on Front Door deployments to immediately avail of additional protection from log4j Remote Command Execution. details at https://www.microsoft.com/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-2-exploitation/",
    "Resource Type": "microsoft.network/frontdoors",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/frontdoors?tabs=json"
}