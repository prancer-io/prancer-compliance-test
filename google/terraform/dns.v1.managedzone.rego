package rule

# https://cloud.google.com/dns/docs/reference/v1/managedZones

#
# PR-GCP-0003-TRF
#

default dnssec_state = null


gc_attribute_absence["dnssec_state"] {
    resource := input.resources[_]
    lower(resource.type) == "google_dns_managed_zone"
    resource.properties.dnssec_config != null
    not resource.properties.dnssec_config[_].state
}

gc_issue["dnssec_state"] {
    resource := input.resources[_]
    lower(resource.type) == "google_dns_managed_zone"
    resource.properties.dnssec_config != null
    lower(resource.properties.dnssec_config[_].state) == "off"
}

dnssec_state {
    lower(input.resources[_].type) == "google_dns_managed_zone"
    not gc_issue["dnssec_state"]
    not gc_attribute_absence["dnssec_state"]
}

dnssec_state = false {
    gc_issue["dnssec_state"]
}

dnssec_state = false {
    gc_attribute_absence["dnssec_state"]
}

dnssec_state_err = "GCP Cloud DNS has DNSSEC disabled" {
    gc_issue["dnssec_state"]
}

dnssec_state_miss_err = "GCP Cloud DNS attribute dnssec.state missing in the resource" {
    gc_attribute_absence["dnssec_state"]
}

dnssec_state_metadata := {
    "Policy Code": "PR-GCP-0003-TRF",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "GCP Cloud DNS has DNSSEC disabled",
    "Policy Description": "This policy identifies GCP Cloud DNS which has DNSSEC disabled. Domain Name System Security Extensions (DNSSEC) adds security to the Domain Name System (DNS) protocol by enabling DNS responses to be validated. Attackers can hijack the process of domain/IP lookup and redirect users to a malicious site through DNS hijacking and man-in-the-middle attacks. DNSSEC helps mitigate the risk of such attacks by cryptographically signing DNS records. As a result, it prevents attackers from issuing fake DNS responses that may misdirect browsers to fake websites.",
    "Resource Type": "google_dns_managed_zone",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/dns/docs/reference/v1/managedZones"
}

#
# PR-GCP-0004-TRF
#

default dnssec_key_rsasha1 = null


gc_attribute_absence["dnssec_key_rsasha1"] {
    resource := input.resources[_]
    lower(resource.type) == "google_dns_managed_zone"
    resource.properties.dnssec_config != null
    not resource.properties.dnssec_config[_].default_key_specs
}

gc_issue["dnssec_key_rsasha1"] {
    resource := input.resources[_]
    lower(resource.type) == "google_dns_managed_zone"
    resource.properties.dnssec_config != null
    key := resource.properties.dnssec_config[_].default_key_specs[_]
    contains(lower(key.key_type), "keysigning")
    contains(lower(key.algorithm), "rsasha1")
}

dnssec_key_rsasha1 {
    lower(input.resources[_].type) == "google_dns_managed_zone"
    not gc_issue["dnssec_key_rsasha1"]
    not gc_attribute_absence["dnssec_key_rsasha1"]
}

dnssec_key_rsasha1 = false {
    gc_issue["dnssec_key_rsasha1"]
}

dnssec_key_rsasha1 = false {
    gc_attribute_absence["dnssec_key_rsasha1"]
}

dnssec_key_rsasha1_err = "GCP Cloud DNS zones using RSASHA1 algorithm for DNSSEC key-signing" {
    gc_issue["dnssec_key_rsasha1"]
}

dnssec_key_rsasha1_miss_err = "GCP Cloud DNS attribute dnssec.default_key_specs missing in the resource" {
    gc_attribute_absence["dnssec_key_rsasha1"]
}

dnssec_key_rsasha1_metadata := {
    "Policy Code": "PR-GCP-0004-TRF",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "GCP Cloud DNS zones using RSASHA1 algorithm for DNSSEC key-signing",
    "Policy Description": "This policy identifies the GCP Cloud DNS zones which are using the RSASHA1 algorithm for DNSSEC key-signing. DNSSEC is a feature of the Domain Name System that authenticates responses to domain name lookups and also prevents attackers from manipulating or poisoning the responses to DNS requests. So the algorithm used for key signing should be recommended one and it should not be weak.",
    "Resource Type": "google_dns_managed_zone",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/dns/docs/reference/v1/managedZones"
}

#
# PR-GCP-0005-TRF
#

default dnssec_zone_rsasha1 = null


gc_attribute_absence["dnssec_zone_rsasha1"] {
    resource := input.resources[_]
    lower(resource.type) == "google_dns_managed_zone"
    resource.properties.dnssec_config != null
    not resource.properties.dnssec_config[_].default_key_specs
}

gc_issue["dnssec_zone_rsasha1"] {
    resource := input.resources[_]
    lower(resource.type) == "google_dns_managed_zone"
    resource.properties.dnssec_config != null
    key := resource.properties.dnssec_config[_].default_key_specs[_]
    contains(lower(key.key_type), "zonesigning")
    contains(lower(key.algorithm), "rsasha1")
}

dnssec_zone_rsasha1 {
    lower(input.resources[_].type) == "google_dns_managed_zone"
    not gc_issue["dnssec_zone_rsasha1"]
    not gc_attribute_absence["dnssec_zone_rsasha1"]
}

dnssec_zone_rsasha1 = false {
    gc_issue["dnssec_zone_rsasha1"]
}

dnssec_zone_rsasha1 = false {
    gc_attribute_absence["dnssec_zone_rsasha1"]
}

dnssec_zone_rsasha1_err = "GCP Cloud DNS zones using RSASHA1 algorithm for DNSSEC zone-signing" {
    gc_issue["dnssec_zone_rsasha1"]
}

dnssec_zone_rsasha1_miss_err = "GCP Cloud DNS attribute dnssec.default_key_specs missing in the resource" {
    gc_attribute_absence["dnssec_zone_rsasha1"]
}

dnssec_zone_rsasha1_metadata := {
    "Policy Code": "PR-GCP-0005-TRF",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "GCP Cloud DNS zones using RSASHA1 algorithm for DNSSEC zone-signing",
    "Policy Description": "This policy identifies the GCP Cloud DNS zones which are using the RSASHA1 algorithm for DNSSEC zone-signing. DNSSEC is a feature of the Domain Name System that authenticates responses to domain name lookups and also prevents attackers from manipulating or poisoning the responses to DNS requests. So the algorithm used for key signing should be recommended one and it should not be weak.",
    "Resource Type": "google_dns_managed_zone",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/dns/docs/reference/v1/managedZones"
}
