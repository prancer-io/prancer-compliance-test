package rego

#
# PR-GCP-TRF-INST-009
#

default compute_ssl_profile_restricted = null

gc_issue["compute_ssl_profile_restricted"] {
    resource := input.resources[i]
    lower(resource.type) == "google_compute_ssl_policy"
    lower(resource.properties.profile) != "custom"
    lower(resource.properties.profile) != "restricted"
}

compute_ssl_profile_restricted {
    lower(input.resources[i].type) == "google_compute_ssl_policy"
    not gc_issue["compute_ssl_profile_restricted"]
}

compute_ssl_profile_restricted = false {
    gc_issue["compute_ssl_profile_restricted"]
}

compute_ssl_profile_restricted_err = "Ensure GCP HTTPS Load balancer SSL Policy is using restrictive profile" {
    gc_issue["compute_ssl_profile_restricted"]
}

compute_ssl_profile_restricted_metadata := {
    "Policy Code": "PR-GCP-TRF-INST-009",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure GCP HTTPS Load balancer SSL Policy is using restrictive profile",
    "Policy Description": "This policy identifies HTTPS Load balancers which are not using restrictive profile in it's SSL Policy, which controls sets of features used in negotiating SSL with clients. As a best security practice, use RESTRICTED as SSL policy profile as it meets stricter compliance requirements and does not include any out-of-date SSL features.",
    "Resource Type": "google_compute_ssl_policy",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
}


#
# PR-GCP-TRF-INST-010
#

deprecated_min_tls_version = ["tls_1_0", "tls_1_1"]

default compute_ssl_min_tls = null

gc_issue["compute_ssl_min_tls"] {
    resource := input.resources[i]
    lower(resource.type) == "google_compute_ssl_policy"
    lower(resource.properties.min_tls_version) == deprecated_min_tls_version[_]
}

compute_ssl_min_tls {
    lower(input.resources[i].type) == "google_compute_ssl_policy"
    not gc_issue["compute_ssl_min_tls"]
}

compute_ssl_min_tls = false {
    gc_issue["compute_ssl_min_tls"]
}

compute_ssl_min_tls_err = "Ensure GCP HTTPS Load balancer is configured with SSL policy not having TLS version 1.1 or lower" {
    gc_issue["compute_ssl_min_tls"]
}

compute_ssl_min_tls_metadata := {
    "Policy Code": "PR-GCP-TRF-INST-010",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure GCP HTTPS Load balancer is configured with SSL policy not having TLS version 1.1 or lower",
    "Policy Description": "This policy identifies HTTPS Load balancers is configured with SSL policy having TLS version 1.1 or lower. As a best security practice, use TLS 1.2 as the minimum TLS version in your load balancers SSL security policies.",
    "Resource Type": "google_compute_ssl_policy",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
}



#
# PR-GCP-TRF-THP-001
#

default lbs_ssl_policy = null

gc_issue["lbs_ssl_policy"] {
    resource := input.resources[i]
    lower(resource.type) == "google_compute_target_https_proxy"
    not resource.properties.ssl_Policy
}

gc_issue["lbs_ssl_policy"] {
    resource := input.resources[i]
    lower(resource.type) == "google_compute_target_https_proxy"
    count(resource.properties.ssl_Policy) == 0
}

gc_issue["lbs_ssl_policy"] {
    resource := input.resources[i]
    lower(resource.type) == "google_compute_target_https_proxy"
    resource.properties.ssl_Policy == null
}

lbs_ssl_policy {
    lower(input.resources[i].type) == "google_compute_target_https_proxy"
    not gc_issue["lbs_ssl_policy"]
}

lbs_ssl_policy = false {
    gc_issue["lbs_ssl_policy"]
}

lbs_ssl_policy_err = "GCP Load balancer HTTPS target proxy configured with default SSL policy instead of custom SSL policy" {
    gc_issue["lbs_ssl_policy"]
}

lbs_ssl_policy_metadata := {
    "Policy Code": "PR-GCP-TRF-THP-001",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "terraform",
    "Policy Title": "GCP Load balancer HTTPS target proxy configured with default SSL policy instead of custom SSL policy",
    "Policy Description": "This policy identifies Load balancer HTTPS target proxies which are configured with default SSL Policy instead of custom SSL policy. It is a best practice to use custom SSL policy to access load balancers. It gives you closer control over SSL/TLS versions and ciphers.",
    "Resource Type": "google_compute_target_https_proxy",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/targetHttpsProxies"
}


#
# PR-GCP-TRF-THP-002
#

default lbs_quic = null

gc_attribute_absence["lbs_quic"] {
    resource := input.resources[i]
    lower(resource.type) == "google_compute_target_https_proxy"
    not resource.properties.quic_override
}

gc_issue["lbs_quic"] {
    resource := input.resources[i]
    lower(resource.type) == "google_compute_target_https_proxy"
    lower(resource.properties.quic_override) != "enable"
}

lbs_quic {
    lower(input.resources[i].type) == "google_compute_target_https_proxy"
    not gc_issue["lbs_quic"]
    not gc_attribute_absence["lbs_quic"]
}

lbs_quic = false {
    gc_issue["lbs_quic"]
}

lbs_quic = false {
    gc_attribute_absence["lbs_quic"]
}

lbs_quic_err = "GCP Load balancer HTTPS target proxy is not configured with QUIC protocol" {
    gc_issue["lbs_quic"]
}

lbs_quic_miss_err = "GCP Load balancer attribute quicOverride missing in the resource" {
    gc_attribute_absence["lbs_quic"]
}

lbs_quic_metadata := {
    "Policy Code": "PR-GCP-TRF-THP-002",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "terraform",
    "Policy Title": "GCP Load balancer HTTPS target proxy is not configured with QUIC protocol",
    "Policy Description": "This policy identifies Load Balancer HTTPS target proxies which are not configured with QUIC protocol. Enabling QUIC protocol in load balancer target https proxies adds advantage by establishing connections faster, stream-based multiplexing, improved loss recovery, and eliminates head-of-line blocking.",
    "Resource Type": "google_compute_target_https_proxy",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/targetHttpsProxies"
}


#
# PR-GCP-TRF-SCP-001
#

default armor_not_config_with_cve = null

gc_issue["armor_not_config_with_cve"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_security_policy"
    rule := resource.rule[_].match[_].expr
    not contains(rule.expression, "cve-canary")
}

gc_issue["armor_not_config_with_cve"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_security_policy"
    rule := resource.rule[_]
    contains(rule.match[_].expr.expression, "cve-canary")
    lower(rule.action) == "allow"
}

armor_not_config_with_cve {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_security_policy"
    not gc_issue["armor_not_config_with_cve"]
}

armor_not_config_with_cve = false {
    gc_issue["armor_not_config_with_cve"]
}

armor_not_config_with_cve_err = "Ensure, GCP Cloud Armor policy not configured with cve-canary rule." {
    gc_issue["armor_not_config_with_cve"]
}

armor_not_config_with_cve_metadata := {
    "Policy Code": "PR-GCP-TRF-SCP-001",
    "Type": "cloud",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "Ensure, GCP Cloud Armor policy not configured with cve-canary rule.",
    "Policy Description": "This policy identifies GCP Cloud Armor rules where cve-canary is not enabled. Preconfigured WAF rule called "cve-canary" can help detect and block exploit attempts of CVE-2021-44228 and CVE-2021-45046 to address the Apache Log4j vulnerability. It is recommended to create a Cloud Armor security policy with rule blocking Apache Log4j exploit attempts. Reference : https://cloud.google.com/blog/products/identity-security/cloud-armor-waf-rule-to-help-address-apache-log4j-vulnerability",
    "Resource Type": "google_compute_security_policy",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/securityPolicies"
}