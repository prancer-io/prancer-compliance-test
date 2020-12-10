package rule

# https://cloud.google.com/dns/docs/reference/v1/managedZones

#
# PR-GCP-0003-GDF
#

default dnssec_state = null


gc_attribute_absence["dnssec_state"] {
    resource := input.json.resources[_]
    lower(resource.type) == "dns.v1.managedzone"
    not resource.properties.dnssecConfig.state
}

gc_issue["dnssec_state"] {
    resource := input.json.resources[_]
    lower(resource.type) == "dns.v1.managedzone"
    lower(resource.properties.dnssecConfig.state) == "off"
}

dnssec_state {
    lower(input.json.resources[_].type) == "dns.v1.managedzone"
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

#
# PR-GCP-0004-GDF
#

default dnssec_key_rsasha1 = null


gc_attribute_absence["dnssec_key_rsasha1"] {
    resource := input.json.resources[_]
    lower(resource.type) == "dns.v1.managedzone"
    not resource.properties.dnssecConfig.defaultKeySpecs
}

gc_issue["dnssec_key_rsasha1"] {
    resource := input.json.resources[_]
    lower(resource.type) == "dns.v1.managedzone"
    key := resource.properties.dnssecConfig.defaultKeySpecs[_]
    contains(lower(key.keyType), "keysigning")
    contains(lower(key.algorithm), "rsasha1")
}

dnssec_key_rsasha1 {
    lower(input.json.resources[_].type) == "dns.v1.managedzone"
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

#
# PR-GCP-0005-GDF
#

default dnssec_zone_rsasha1 = null


gc_attribute_absence["dnssec_zone_rsasha1"] {
    resource := input.json.resources[_]
    lower(resource.type) == "dns.v1.managedzone"
    not resource.properties.dnssecConfig.defaultKeySpecs
}

gc_issue["dnssec_zone_rsasha1"] {
    resource := input.json.resources[_]
    lower(resource.type) == "dns.v1.managedzone"
    key := resource.properties.dnssecConfig.defaultKeySpecs[_]
    contains(lower(key.keyType), "zonesigning")
    contains(lower(key.algorithm), "rsasha1")
}

dnssec_zone_rsasha1 {
    lower(input.json.resources[_].type) == "dns.v1.managedzone"
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
