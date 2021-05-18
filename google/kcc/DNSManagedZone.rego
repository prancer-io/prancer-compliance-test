package rule

# https://cloud.google.com/config-connector/docs/reference/resource-docs/dns/dnsmanagedzone

#
# DNSSEC_DISABLED
#

default dnssec_disabled = null


gc_attribute_absence["dnssec_disabled"] {
    lower(input.kind) == "dnsmanagedzone"
    not input.spec.dnssecConfig.state
}

gc_issue["dnssec_disabled"] {
    lower(input.kind) == "dnsmanagedzone"
    lower(input.spec.dnssecConfig.state) != "on"
}

dnssec_disabled {
    lower(input.kind) == "dnsmanagedzone"
    not gc_issue["dnssec_disabled"]
    not gc_attribute_absence["dnssec_disabled"]
}

dnssec_disabled = false {
    gc_issue["dnssec_disabled"]
}

dnssec_disabled = false {
    gc_attribute_absence["dnssec_disabled"]
}

dnssec_disabled_err = "GCP Cloud DNS has DNSSEC disabled" {
    gc_issue["dnssec_disabled"]
}

dnssec_disabled_miss_err = "GCP Cloud DNS attribute dnssecConfig.state missing in the resource" {
    gc_attribute_absence["dnssec_disabled"]
}

#
# RSASHA1_FOR_SIGNING
#

default rsasha1_for_signing = null


gc_attribute_absence["rsasha1_for_signing"] {
    lower(input.kind) == "dnsmanagedzone"
    not input.spec.dnssecConfig.defaultKeySpecs
}

gc_issue["rsasha1_for_signing"] {
    lower(input.kind) == "dnsmanagedzone"
    key := input.spec.dnssecConfig.defaultKeySpecs[_]
    contains(lower(key.keyType), "keysigning")
    contains(lower(key.algorithm), "rsasha1")
}

rsasha1_for_signing {
    lower(input.kind) == "dnsmanagedzone"
    not gc_issue["rsasha1_for_signing"]
    not gc_attribute_absence["rsasha1_for_signing"]
}

rsasha1_for_signing = false {
    gc_issue["rsasha1_for_signing"]
}

rsasha1_for_signing = false {
    gc_attribute_absence["rsasha1_for_signing"]
}

rsasha1_for_signing_err = "GCP Cloud DNS zones using RSASHA1 algorithm for DNSSEC key-signing" {
    gc_issue["rsasha1_for_signing"]
}

rsasha1_for_signing_miss_err = "GCP Cloud DNS attribute dnssecConfig.defaultKeySpecs missing in the resource" {
    gc_attribute_absence["rsasha1_for_signing"]
}
