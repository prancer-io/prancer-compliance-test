
#
# PR-GCP-TRF-PUB-001
#

default pub_sub_kms = null

gc_issue["pub_sub_kms"] {
    resource := input.resources[i]
    lower(resource.type) == "google_pubsub_topic"
    not resource.properties.kms_key_name
}

gc_issue["pub_sub_kms"] {
    resource := input.resources[i]
    lower(resource.type) == "google_pubsub_topic"
    count(resource.properties.kms_key_name) == 0
}

gc_issue["pub_sub_kms"] {
    resource := input.resources[i]
    lower(resource.type) == "google_pubsub_topic"
    resource.properties.kms_key_name == null
}

pub_sub_kms {
    lower(input.resources[i].type) == "google_pubsub_topic"
    not gc_issue["pub_sub_kms"]
}

pub_sub_kms = false {
    gc_issue["pub_sub_kms"]
}

pub_sub_kms = false {
    gc_attribute_absence["pub_sub_kms"]
}

pub_sub_kms_err = "Ensure GCP Pub/Sub topic is encrypted using a customer-managed encryption key" {
    gc_issue["pub_sub_kms"]
}

pub_sub_kms_metadata := {
    "Policy Code": "PR-GCP-TRF-PUB-001",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "terraform",
    "Policy Title": "Ensure GCP Pub/Sub topic is encrypted using a customer-managed encryption key",
    "Policy Description": "This policy identifies GCP Pub/Sub topics that are not encrypted using a customer-managed encryption key. It is a best practice to use customer-managed KMS Keys to encrypt your Pub/Sub topic. Customer-managed CMKs give you more flexibility, including the ability to create, rotate, disable, define access control for, and audit the encryption keys used to help protect your data.\n\nReference: https://cloud.google.com/pubsub/docs/encryption",
    "Resource Type": "google_pubsub_topic",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/pubsub/docs/reference/rest/v1/projects.topics"
}
