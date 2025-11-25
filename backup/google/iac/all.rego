package rule


#
# PR-GCP-GDF-PUB-001
#

default pub_sub_kms = null

gc_issue["pub_sub_kms"] {
    resource := input.resources[i]
    lower(resource.type) == "pubsub.v1.topic"
    not resource.properties.kmsKeyName
}

gc_issue["pub_sub_kms"] {
    resource := input.resources[i]
    lower(resource.type) == "pubsub.v1.topic"
    count(resource.properties.kmsKeyName) == 0
}

gc_issue["pub_sub_kms"] {
    resource := input.resources[i]
    lower(resource.type) == "pubsub.v1.topic"
    resource.properties.kmsKeyName == null
}

pub_sub_kms {
    lower(input.resources[i].type) == "pubsub.v1.topic"
    not gc_issue["pub_sub_kms"]
}

pub_sub_kms = false {
    gc_issue["pub_sub_kms"]
}

pub_sub_kms_err = "Ensure GCP Pub/Sub topic is encrypted using a customer-managed encryption key" {
    gc_issue["pub_sub_kms"]
}

pub_sub_kms_metadata := {
    "Policy Code": "PR-GCP-GDF-PUB-001",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "Ensure GCP Pub/Sub topic is encrypted using a customer-managed encryption key",
    "Policy Description": "This policy identifies GCP Pub/Sub topics that are not encrypted using a customer-managed encryption key. It is a best practice to use customer-managed KMS Keys to encrypt your Pub/Sub topic. Customer-managed CMKs give you more flexibility, including the ability to create, rotate, disable, define access control for, and audit the encryption keys used to help protect your data.\n\nReference: https://cloud.google.com/pubsub/docs/encryption",
    "Resource Type": "pubsub.v1.topic",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/pubsub/docs/reference/rest/v1/projects.topics"
}
