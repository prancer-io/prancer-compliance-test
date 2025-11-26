package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.network/azurefirewalls?tabs=json

#
# PR-AZR-CLD-AFW-001
#

default azure_firewall_configured_with_idpc_and_tls_inspection = null

azure_attribute_absence["azure_firewall_configured_with_idpc_and_tls_inspection"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/azurefirewalls"
    not resource.properties.sku.tier
}

azure_attribute_absence["azure_firewall_configured_with_idpc_and_tls_inspection"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/azurefirewalls"
    not resource.properties.firewallPolicy.id
}

azure_issue["azure_firewall_configured_with_idpc_and_tls_inspection"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/azurefirewalls"
    lower(resource.properties.sku.tier) != "premium"
}

azure_issue["azure_firewall_configured_with_idpc_and_tls_inspection"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/azurefirewalls"
    count(resource.properties.firewallPolicy.id) == 0
}

azure_attribute_absence["azure_firewall_configured_with_idpc_and_tls_inspection"] {
    count([c | lower(input.resources[_].type) == "microsoft.network/firewallpolicies"; c := 1]) == 0
}

azure_attribute_absence["azure_firewall_configured_with_idpc_and_tls_inspection"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/firewallpolicies"
    not resource.properties.sku.tier
}

azure_attribute_absence["azure_firewall_configured_with_idpc_and_tls_inspection"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/firewallpolicies"
    not resource.properties.intrusionDetection.mode
}

azure_attribute_absence["azure_firewall_configured_with_idpc_and_tls_inspection"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/firewallpolicies"
    not resource.properties.transportSecurity.certificateAuthority.keyVaultSecretId
}

azure_issue["azure_firewall_configured_with_idpc_and_tls_inspection"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/firewallpolicies"
    lower(resource.properties.sku.tier) != "premium"
}

azure_issue["azure_firewall_configured_with_idpc_and_tls_inspection"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/firewallpolicies"
    lower(resource.properties.intrusionDetection.mode) != "deny"
}

azure_issue["azure_firewall_configured_with_idpc_and_tls_inspection"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/firewallpolicies"
    count(resource.properties.transportSecurity.certificateAuthority.keyVaultSecretId) == 0
}

azure_firewall_configured_with_idpc_and_tls_inspection {
    lower(input.resources[_].type) == "microsoft.network/azurefirewalls"
    not azure_attribute_absence["azure_firewall_configured_with_idpc_and_tls_inspection"]
    not azure_issue["azure_firewall_configured_with_idpc_and_tls_inspection"]
}

azure_firewall_configured_with_idpc_and_tls_inspection = false {
    lower(input.resources[_].type) == "microsoft.network/azurefirewalls"
    azure_issue["azure_firewall_configured_with_idpc_and_tls_inspection"]
}

azure_firewall_configured_with_idpc_and_tls_inspection = false {
    lower(input.resources[_].type) == "microsoft.network/azurefirewalls"
    azure_attribute_absence["azure_firewall_configured_with_idpc_and_tls_inspection"]
}

azure_firewall_configured_with_idpc_and_tls_inspection_err = "Azure Firewall Premium currently not configured with both IDPS Alert & Deny mode and TLS inspection enabled" {
    lower(input.resources[_].type) == "microsoft.network/azurefirewalls"
    azure_issue["azure_firewall_configured_with_idpc_and_tls_inspection"]
} else = "'microsoft.network/azurefirewalls' resource property 'tier' under 'sku' block need to be exist and 'id' of 'microsoft.network/firewallpolicies' resource need to be exist under 'firewallPolicy' block. Also 'intrusionDetection' and 'transportSecurity' block need to be exist under 'microsoft.network/firewallpolicies' and property 'tier' under 'sku' block need to be exist as well. one or all are missing." {
    lower(input.resources[_].type) == "microsoft.network/azurefirewalls"
    azure_attribute_absence["azure_firewall_configured_with_idpc_and_tls_inspection"]
}

azure_firewall_configured_with_idpc_and_tls_inspection_metadata := {
    "Policy Code": "PR-AZR-CLD-AFW-001",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure Firewall Premium should be configured with both IDPS Alert & Deny mode and TLS inspection enabled for proactive protection against CVE-2021-44228 exploit",
    "Policy Description": "Azure Firewall Premium has enhanced protection from the Log4j RCE CVE-2021-44228 vulnerability and exploit. Azure Firewall premium IDPS (Intrusion Detection and Prevention System) provides IDPS inspection for all east-west traffic and outbound traffic to internet. details at https://www.microsoft.com/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-2-exploitation/",
    "Resource Type": "microsoft.network/azurefirewalls",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/azurefirewalls?tabs=json"
}