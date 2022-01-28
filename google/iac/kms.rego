package rule

#
# PR-GCP-GDF-KMS-001
#

default kms_key_rotation = null

gc_issue["kms_key_rotation"] {
    resource := input.resources[i]
    lower(resource.type) == "kms.v1.projects.locations.keyRings.cryptoKeys"
    not resource.properties.rotationPeriod
}

gc_issue["kms_key_rotation"] {
    resource := input.resources[i]
    lower(resource.type) == "kms.v1.projects.locations.keyRings.cryptoKeys"
    resource.properties.rotationPeriod > 7776000
}

kms_key_rotation {
    lower(input.resources[i].type) == "kms.v1.projects.locations.keyRings.cryptoKeys"
    not gc_issue["kms_key_rotation"]
}

kms_key_rotation = false {
    gc_issue["kms_key_rotation"]
}

kms_key_rotation_err = "Ensure GCP KMS encryption key rotating in every 90 days" {
    gc_issue["kms_key_rotation"]
}

kms_key_rotation_metadata := {
    "Policy Code": "PR-GCP-GDF-KMS-001",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "Ensure GCP KMS encryption key rotating in every 90 days",
    "Policy Description": "This policy identifies GCP KMS encryption keys that are not rotating every 90 days.  A key is used to protect some corpus of data. A collection of files could be encrypted with the same key and people with decrypt permissions on that key would be able to decrypt those files. It's recommended to make sure the 'rotation period' is set to a specific time to ensure data cannot be accessed through the old key.",
    "Resource Type": "kms.v1.projects.locations.keyRings.cryptoKeys",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys"
}
