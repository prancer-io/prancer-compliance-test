package rule

# https://github.com/GoogleCloudPlatform/k8s-config-connector/blob/master/samples/resources/iamserviceaccountkey/iam_v1beta1_iamserviceaccountkey.yaml

#
# PR-GCP-0067-KCC
#

default svc_account_key = null


gc_attribute_absence["svc_account_key"] {
    lower(input.kind) == "iamserviceaccountkey"
    not input.spec.name
}

gc_issue["svc_account_key"] {
    lower(input.kind) == "iamserviceaccountkey"
    contains(lower(input.spec.name), "iam.gserviceaccount.com")
    time.now_ns() - time.parse_rfc3339_ns(input.spec.validAfter) > 7776000000000000
}

svc_account_key {
    lower(input.kind) == "iamserviceaccountkey"
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
