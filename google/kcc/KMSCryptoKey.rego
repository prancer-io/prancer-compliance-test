package rule

# https://cloud.google.com/config-connector/docs/reference/resource-docs/kms/kmscryptokey

#
# KMS_KEY_NOT_ROTATED
# PR-GCP-0055-KCC

default kms_key_not_rotated = null

gc_issue["kms_key_not_rotated"] {
    lower(input.kind) == "kmscryptokey"
    count([c | input.spec.auditConfigs[_].auditLogConfigs; c := 1]) == 0
}

kms_key_not_rotated {
    lower(input.kind) == "kmscryptokey"
    not gc_issue["kms_key_not_rotated"]
}

kms_key_not_rotated = false {
    gc_issue["kms_key_not_rotated"]
}

kms_key_not_rotated_err = "Rotation isn't configured on a Cloud KMS encryption key." {
    gc_issue["kms_key_not_rotated"]
}

kms_key_not_rotated_metadata := {
    "Policy Code": "KMS_KEY_NOT_ROTATED",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "KCC",
    "Policy Title": "KMS Key Not Rotated",
    "Policy Description": "Rotation isn't configured on a Cloud KMS encryption key.",
    "Resource Type": "KMSCryptoKey",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/config-connector/docs/reference/resource-docs/kms/kmscryptokey"
}
