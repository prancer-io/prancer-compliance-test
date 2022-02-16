package rule

# https://cloud.google.com/dns/docs/reference/v1/managedZones

#
# PR-GCP-CLD-MZ-001
#

default dnssec_state = null


gc_attribute_absence["dnssec_state"] {
    # lower(resource.type) == "dns.v1.managedzone"
    not input.dnssecConfig.state
}

source_path[{"dnssec_state": metadata}] {
    # lower(resource.type) == "dns.v1.managedzone"
    not input.dnssecConfig.state
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "dnssecConfig", "state"]
        ],
    }
}

gc_issue["dnssec_state"] {
    # lower(resource.type) == "dns.v1.managedzone"
    lower(input.dnssecConfig.state) == "off"
}

source_path[{"dnssec_state": metadata}] {
    # lower(resource.type) == "dns.v1.managedzone"
    lower(input.dnssecConfig.state) == "off"
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "dnssecConfig", "state"]
        ],
    }
}

dnssec_state {
    # lower(input.resources[i].type) == "dns.v1.managedzone"
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

dnssec_state_miss_err = "GCP Cloud DNS attribute dnssecConfig.state missing in the resource" {
    gc_attribute_absence["dnssec_state"]
}

dnssec_state_metadata := {
    "Policy Code": "PR-GCP-CLD-MZ-001",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "GCP Cloud DNS has DNSSEC disabled",
    "Policy Description": "This policy identifies GCP Cloud DNS which has DNSSEC disabled. Domain Name System Security Extensions (DNSSEC) adds security to the Domain Name System (DNS) protocol by enabling DNS responses to be validated. Attackers can hijack the process of domain/IP lookup and redirect users to a malicious site through DNS hijacking and man-in-the-middle attacks. DNSSEC helps mitigate the risk of such attacks by cryptographically signing DNS records. As a result, it prevents attackers from issuing fake DNS responses that may misdirect browsers to fake websites.",
    "Resource Type": "dns.v1.managedzone",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/dns/docs/reference/v1/managedZones"
}

#
# PR-GCP-CLD-MZ-002
#

default dnssec_key_rsasha1 = null


gc_attribute_absence["dnssec_key_rsasha1"] {
    # lower(resource.type) == "dns.v1.managedzone"
    not input.dnssecConfig.defaultKeySpecs
}

source_path[{"dnssec_key_rsasha1": metadata}] {
    # lower(resource.type) == "dns.v1.managedzone"
    not input.dnssecConfig.defaultKeySpecs
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "dnssecConfig", "defaultKeySpecs"]
        ],
    }
}

gc_issue["dnssec_key_rsasha1"] {
    # lower(resource.type) == "dns.v1.managedzone"
    key := input.dnssecConfig.defaultKeySpecs[j]
    contains(lower(key.keyType), "keysigning")
    contains(lower(key.algorithm), "rsasha1")
}

source_path[{"dnssec_key_rsasha1": metadata}] {
    # lower(resource.type) == "dns.v1.managedzone"
    key := input.dnssecConfig.defaultKeySpecs[j]
    contains(lower(key.keyType), "keysigning")
    contains(lower(key.algorithm), "rsasha1")
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "dnssecConfig", "defaultKeySpecs", j, "algorithm"]
        ],
    }
}

dnssec_key_rsasha1 {
    # lower(input.resources[i].type) == "dns.v1.managedzone"
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

dnssec_key_rsasha1_miss_err = "GCP Cloud DNS attribute dnssecConfig.defaultKeySpecs missing in the resource" {
    gc_attribute_absence["dnssec_key_rsasha1"]
}

dnssec_key_rsasha1_metadata := {
    "Policy Code": "PR-GCP-CLD-MZ-002",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "GCP Cloud DNS zones using RSASHA1 algorithm for DNSSEC key-signing",
    "Policy Description": "This policy identifies the GCP Cloud DNS zones which are using the RSASHA1 algorithm for DNSSEC key-signing. DNSSEC is a feature of the Domain Name System that authenticates responses to domain name lookups and also prevents attackers from manipulating or poisoning the responses to DNS requests. So the algorithm used for key signing should be recommended one and it should not be weak.",
    "Resource Type": "dns.v1.managedzone",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/dns/docs/reference/v1/managedZones"
}

#
# PR-GCP-CLD-MZ-003
#

default dnssec_zone_rsasha1 = null


gc_attribute_absence["dnssec_zone_rsasha1"] {
    # lower(resource.type) == "dns.v1.managedzone"
    not input.dnssecConfig.defaultKeySpecs
}

source_path[{"dnssec_zone_rsasha1": metadata}] {
    # lower(resource.type) == "dns.v1.managedzone"
    not input.dnssecConfig.defaultKeySpecs
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "dnssecConfig", "defaultKeySpecs"]
        ],
    }
}

gc_issue["dnssec_zone_rsasha1"] {
    # lower(resource.type) == "dns.v1.managedzone"
    key := input.dnssecConfig.defaultKeySpecs[j]
    contains(lower(key.keyType), "zonesigning")
    contains(lower(key.algorithm), "rsasha1")
}

source_path[{"dnssec_zone_rsasha1": metadata}] {
    # lower(resource.type) == "dns.v1.managedzone"
    key := input.dnssecConfig.defaultKeySpecs[j]
    contains(lower(key.keyType), "zonesigning")
    contains(lower(key.algorithm), "rsasha1")
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "dnssecConfig", "defaultKeySpecs", j, "algorithm"]
        ],
    }
}

dnssec_zone_rsasha1 {
    # lower(input.resources[i].type) == "dns.v1.managedzone"
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

dnssec_zone_rsasha1_miss_err = "GCP Cloud DNS attribute dnssecConfig.defaultKeySpecs missing in the resource" {
    gc_attribute_absence["dnssec_zone_rsasha1"]
}

dnssec_zone_rsasha1_metadata := {
    "Policy Code": "PR-GCP-CLD-MZ-003",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "GCP Cloud DNS zones using RSASHA1 algorithm for DNSSEC zone-signing",
    "Policy Description": "This policy identifies the GCP Cloud DNS zones which are using the RSASHA1 algorithm for DNSSEC zone-signing. DNSSEC is a feature of the Domain Name System that authenticates responses to domain name lookups and also prevents attackers from manipulating or poisoning the responses to DNS requests. So the algorithm used for key signing should be recommended one and it should not be weak.",
    "Resource Type": "dns.v1.managedzone",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/dns/docs/reference/v1/managedZones"
}
