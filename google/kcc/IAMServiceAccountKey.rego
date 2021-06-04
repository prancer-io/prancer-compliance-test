package rule

# https://cloud.google.com/config-connector/docs/reference/resource-docs/iam/iamserviceaccountkey

#
# SERVICE_ACCOUNT_KEY_NOT_ROTATED
# PR-GCP-0054-KCC

default service_account_key_not_rotated = null

gc_issue["service_account_key_not_rotated"] {
    lower(input.kind) == "iamserviceaccountkey"
    time.now_ns() - time.parse_rfc3339_ns(input.spec.validAfter) > 7776000000000000
}

service_account_key_not_rotated {
    lower(input.kind) == "iamserviceaccountkey"
    not gc_issue["service_account_key_not_rotated"]
}

service_account_key_not_rotated = false {
    gc_issue["service_account_key_not_rotated"]
}

service_account_key_not_rotated_err = "A service account key hasn't been rotated for more than 90 days" {
    gc_issue["service_account_key_not_rotated"]
}

service_account_key_not_rotated_metadata := {
    "Policy Code": "SERVICE_ACCOUNT_KEY_NOT_ROTATED",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "KCC",
    "Policy Title": "Service Account Key Not Rotated",
    "Policy Description": "A service account key hasn't been rotated for more than 90 days",
    "Resource Type": "IAMServiceAccountKey",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/config-connector/docs/reference/resource-docs/iam/iamserviceaccountkey"
}
