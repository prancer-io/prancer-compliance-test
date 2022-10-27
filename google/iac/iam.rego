package rule

# https://cloud.google.com/iam/reference/rest/v1/projects.serviceAccounts.keys

#
# PR-GCP-GDF-SAK-001
#

default svc_account_key = null


gc_attribute_absence["svc_account_key"] {
    resource := input.resources[i]
    lower(resource.type) == "iam.v1.serviceaccounts.key"
    not resource.properties.name
}

source_path[{"svc_account_key": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "iam.v1.serviceaccounts.key"
    not resource.properties.name
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "name"]
        ],
    }
}

gc_issue["svc_account_key"] {
    resource := input.resources[i]
    lower(resource.type) == "iam.v1.serviceaccounts.key"
    contains(lower(resource.properties.name), "iam.gserviceaccount.com")
    time.now_ns() - time.parse_rfc3339_ns(resource.properties.validAfterTime) > 7776000000000000
}

source_path[{"svc_account_key": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "iam.v1.serviceaccounts.key"
    contains(lower(resource.properties.name), "iam.gserviceaccount.com")
    time.now_ns() - time.parse_rfc3339_ns(resource.properties.validAfterTime) > 7776000000000000
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "validAfterTime"]
        ],
    }
}


svc_account_key {
    lower(input.resources[i].type) == "iam.v1.serviceaccounts.key"
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

svc_account_key_metadata := {
    "Policy Code": "PR-GCP-GDF-SAK-001",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "GCP User managed service account keys are not rotated for 90 days",
    "Policy Description": "This policy identifies user-managed service account keys which are not rotated from last 90 days or more. Rotating Service Account keys will reduce the window of opportunity for an access key that is associated with a compromised or terminated account to be used. Service Account keys should be rotated to ensure that data cannot be accessed with an old key which might have been lost, cracked, or stolen. It is recommended that all user-managed service account keys are regularly rotated.",
    "Resource Type": "iam.v1.serviceaccounts.key",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/iam/reference/rest/v1/projects.serviceAccounts.keys"
}