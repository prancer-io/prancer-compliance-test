package rule

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


#
# PR-GCP-GDF-WAF-001
#

default waf_log4j_vulnerability = null

gc_issue["waf_log4j_vulnerability"] {
    resource := input.resources[i]
    lower(resource.type) == "google_compute_security_policy"
    count([c | lower(resource.properties.rule[_].match[_].expr[_].expression) == "evaluatepreconfiguredexpr('cve-canary')"; c:=1]) == 0
}

waf_log4j_vulnerability {
    lower(input.resources[i].type) == "google_compute_security_policy"
    not gc_issue["waf_log4j_vulnerability"]
}

waf_log4j_vulnerability = false {
    gc_issue["waf_log4j_vulnerability"]
}

waf_log4j_vulnerability_err = "Ensure GCP Pub/Sub topic is encrypted using a customer-managed encryption key" {
    gc_issue["waf_log4j_vulnerability"]
}

waf_log4j_vulnerability_metadata := {
    "Policy Code": "PR-GCP-GDF-WAF-001",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "Ensure GCP Pub/Sub topic is encrypted using a customer-managed encryption key",
    "Policy Description": "This policy identifies GCP Pub/Sub topics that are not encrypted using a customer-managed encryption key. It is a best practice to use customer-managed KMS Keys to encrypt your Pub/Sub topic. Customer-managed CMKs give you more flexibility, including the ability to create, rotate, disable, define access control for, and audit the encryption keys used to help protect your data.\n\nReference: https://cloud.google.com/pubsub/docs/encryption",
    "Resource Type": "google_compute_security_policy",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/pubsub/docs/reference/rest/v1/projects.topics"
}
