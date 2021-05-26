package rule

# https://cloud.google.com/config-connector/docs/reference/resource-docs/dns/dnsmanagedzone

#
# DNSSEC_DISABLED
#

default dnssec_disabled = null


gc_issue["dnssec_disabled"] {
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
}

dnssec_disabled = false {
    gc_issue["dnssec_disabled"]
}

dnssec_disabled_err = "DNSSEC is disabled for Cloud DNS zones." {
    gc_issue["dnssec_disabled"]
}

dnssec_disabled_metadata := {
    "Policy Code": "DNSSEC_DISABLED",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "KCC",
    "Policy Title": "DNSSEC Disabled",
    "Policy Description": "DNSSEC is disabled for Cloud DNS zones.",
    "Resource Type": "DNSManagedZone",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/config-connector/docs/reference/resource-docs/dns/dnsmanagedzone"
}

#
# RSASHA1_FOR_SIGNING
#

default rsasha1_for_signing = null

gc_issue["rsasha1_for_signing"] {
    lower(input.kind) == "dnsmanagedzone"
    key := input.spec.dnssecConfig.defaultKeySpecs[_]
    contains(lower(key.keyType), "keysigning")
    contains(lower(key.algorithm), "rsasha1")
}

rsasha1_for_signing {
    lower(input.kind) == "dnsmanagedzone"
    not gc_issue["rsasha1_for_signing"]
}

rsasha1_for_signing = false {
    gc_issue["rsasha1_for_signing"]
}

rsasha1_for_signing_err = "RSASHA1 is used for key signing in Cloud DNS zones." {
    gc_issue["rsasha1_for_signing"]
}

rsasha1_for_signing_metadata := {
    "Policy Code": "RSASHA1_FOR_SIGNING",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "KCC",
    "Policy Title": "RSASHA1 For Signing",
    "Policy Description": "RSASHA1 is used for key signing in Cloud DNS zones.",
    "Resource Type": "DNSManagedZone",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/config-connector/docs/reference/resource-docs/dns/dnsmanagedzone"
}
