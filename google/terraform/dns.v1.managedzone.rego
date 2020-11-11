package rule

# https://cloud.google.com/dns/docs/reference/v1/managedZones

#
# Id: 273
#

default dnssec_state = null


gc_attribute_absence["dnssec_state"] {
    resource := input.json.resources[_]
    lower(resource.type) == "google_dns_managed_zone"
    not resource.properties.dnssec_config.state
}

gc_issue["dnssec_state"] {
    resource := input.json.resources[_]
    lower(resource.type) == "google_dns_managed_zone"
    lower(resource.properties.dnssec_config.state) == "off"
}

dnssec_state {
    lower(input.json.resources[_].type) == "google_dns_managed_zone"
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

#
# Id: 274
#

default dnssec_key_rsasha1 = null


gc_attribute_absence["dnssec_key_rsasha1"] {
    resource := input.json.resources[_]
    lower(resource.type) == "google_dns_managed_zone"
    not resource.properties.dnssec_config.default_key_specs
}

gc_issue["dnssec_key_rsasha1"] {
    resource := input.json.resources[_]
    lower(resource.type) == "google_dns_managed_zone"
    key := resource.properties.dnssec_config.default_key_specs[_]
    contains(lower(key.key_type), "keysigning")
    contains(lower(key.algorithm), "rsasha1")
}

dnssec_key_rsasha1 {
    lower(input.json.resources[_].type) == "google_dns_managed_zone"
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

#
# Id: 275
#

default dnssec_zone_rsasha1 = null


gc_attribute_absence["dnssec_zone_rsasha1"] {
    resource := input.json.resources[_]
    lower(resource.type) == "google_dns_managed_zone"
    not resource.properties.dnssec_config.default_key_specs
}

gc_issue["dnssec_zone_rsasha1"] {
    resource := input.json.resources[_]
    lower(resource.type) == "google_dns_managed_zone"
    key := resource.properties.dnssec_config.default_key_specs[_]
    contains(lower(key.key_type), "zonesigning")
    contains(lower(key.algorithm), "rsasha1")
}

dnssec_zone_rsasha1 {
    lower(input.json.resources[_].type) == "google_dns_managed_zone"
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
