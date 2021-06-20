package rule

# https://cloud.google.com/dns/docs/reference/v1/managedZones

#
# PR-GCP-0003-GDF
#

default dnssec_state = null


gc_attribute_absence["dnssec_state"] {
    resource := input.resources[_]
    lower(resource.type) == "dns.v1.managedzone"
    not resource.properties.dnssecConfig.state
}

gc_issue["dnssec_state"] {
    resource := input.resources[_]
    lower(resource.type) == "dns.v1.managedzone"
    lower(resource.properties.dnssecConfig.state) == "off"
}

dnssec_state {
    lower(input.resources[_].type) == "dns.v1.managedzone"
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

dnssec_state_err = "GCP Cloud DNS attribute dnssecConfig.state missing in the resource" {
    gc_attribute_absence["dnssec_state"]
}

dnssec_state_metadata := {
    "Policy Code": "PR-GCP-0003-GDF",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "GCP Cloud DNS has DNSSEC disabled",
    "Policy Description": "This policy identifies GCP Cloud DNS which has DNSSEC disabled. Domain Name System Security Extensions (DNSSEC) adds security to the Domain Name System (DNS) protocol by enabling DNS responses to be validated. Attackers can hijack the process of domain/IP lookup and redirect users to a malicious site through DNS hijacking and man-in-the-middle attacks. DNSSEC helps mitigate the risk of such attacks by cryptographically signing DNS records. As a result, it prevents attackers from issuing fake DNS responses that may misdirect browsers to fake websites.",
    "Resource Type": "dns.v1.managedzone",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/dns/docs/reference/v1/managedZones"
}

#
# PR-GCP-0004-GDF
#

default dnssec_key_rsasha1 = null


gc_attribute_absence["dnssec_key_rsasha1"] {
    resource := input.resources[_]
    lower(resource.type) == "dns.v1.managedzone"
    not resource.properties.dnssecConfig.defaultKeySpecs
}

gc_issue["dnssec_key_rsasha1"] {
    resource := input.resources[_]
    lower(resource.type) == "dns.v1.managedzone"
    key := resource.properties.dnssecConfig.defaultKeySpecs[_]
    contains(lower(key.keyType), "keysigning")
    contains(lower(key.algorithm), "rsasha1")
}

dnssec_key_rsasha1 {
    lower(input.resources[_].type) == "dns.v1.managedzone"
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

dnssec_key_rsasha1_err = "GCP Cloud DNS attribute dnssecConfig.defaultKeySpecs missing in the resource" {
    gc_attribute_absence["dnssec_key_rsasha1"]
}

dnssec_key_rsasha1_metadata := {
    "Policy Code": "PR-GCP-0004-GDF",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "GCP Cloud DNS zones using RSASHA1 algorithm for DNSSEC key-signing",
    "Policy Description": "This policy identifies the GCP Cloud DNS zones which are using the RSASHA1 algorithm for DNSSEC key-signing. DNSSEC is a feature of the Domain Name System that authenticates responses to domain name lookups and also prevents attackers from manipulating or poisoning the responses to DNS requests. So the algorithm used for key signing should be recommended one and it should not be weak.",
    "Resource Type": "dns.v1.managedzone",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/dns/docs/reference/v1/managedZones"
}

#
# PR-GCP-0005-GDF
#

default dnssec_zone_rsasha1 = null


gc_attribute_absence["dnssec_zone_rsasha1"] {
    resource := input.resources[_]
    lower(resource.type) == "dns.v1.managedzone"
    not resource.properties.dnssecConfig.defaultKeySpecs
}

gc_issue["dnssec_zone_rsasha1"] {
    resource := input.resources[_]
    lower(resource.type) == "dns.v1.managedzone"
    key := resource.properties.dnssecConfig.defaultKeySpecs[_]
    contains(lower(key.keyType), "zonesigning")
    contains(lower(key.algorithm), "rsasha1")
}

dnssec_zone_rsasha1 {
    lower(input.resources[_].type) == "dns.v1.managedzone"
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

dnssec_zone_rsasha1_err = "GCP Cloud DNS attribute dnssecConfig.defaultKeySpecs missing in the resource" {
    gc_attribute_absence["dnssec_zone_rsasha1"]
}

dnssec_zone_rsasha1_metadata := {
    "Policy Code": "PR-GCP-0005-GDF",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "GCP Cloud DNS zones using RSASHA1 algorithm for DNSSEC zone-signing",
    "Policy Description": "This policy identifies the GCP Cloud DNS zones which are using the RSASHA1 algorithm for DNSSEC zone-signing. DNSSEC is a feature of the Domain Name System that authenticates responses to domain name lookups and also prevents attackers from manipulating or poisoning the responses to DNS requests. So the algorithm used for key signing should be recommended one and it should not be weak.",
    "Resource Type": "dns.v1.managedzone",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/dns/docs/reference/v1/managedZones"
}
