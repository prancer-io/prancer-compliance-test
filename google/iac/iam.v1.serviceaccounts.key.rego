package rule

# https://cloud.google.com/iam/reference/rest/v1/projects.serviceAccounts.keys

#
# PR-GCP-0067-CFR
#

default svc_account_key = null


gc_attribute_absence["svc_account_key"] {
    resource := input.json.resources[_]
    lower(resource.type) == "iam.v1.serviceaccounts.key"
    not resource.properties.name
}

gc_issue["svc_account_key"] {
    resource := input.json.resources[_]
    lower(resource.type) == "iam.v1.serviceaccounts.key"
    contains(lower(resource.properties.name), "iam.gserviceaccount.com")
    time.now_ns() - time.parse_rfc3339_ns(resource.properties.validAfterTime) > 7776000000000000
}

svc_account_key {
    lower(input.json.resources[_].type) == "iam.v1.serviceaccounts.key"
    not gc_issue["svc_account_key"]
    not gc_attribute_absence["svc_account_key"]
}

svc_account_key = false {
    gc_issue["svc_account_key"]
}

svc_account_key = false {
    gc_attribute_absence["svc_account_key"]
}

svc_account_key_err = "GCP User managed service account keys are not rotated for 90 days" {
    gc_issue["svc_account_key"]
}

svc_account_key_miss_err = "GCP User managed service account keys attribute name missing in the resource" {
    gc_attribute_absence["svc_account_key"]
}
