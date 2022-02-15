package rule


#
# PR-GCP-CLD-PUB-001
#

default pub_sub_kms = null

gc_issue["pub_sub_kms"] {
    # lower(resource.type) == "pubsub.v1.topic"
    not input.kmsKeyName
}

gc_issue["pub_sub_kms"] {
    # lower(resource.type) == "pubsub.v1.topic"
    count(input.kmsKeyName) == 0
}

gc_issue["pub_sub_kms"] {
    # lower(resource.type) == "pubsub.v1.topic"
    input.kmsKeyName == null
}

pub_sub_kms {
    # lower(input.resources[i].type) == "pubsub.v1.topic"
    not gc_issue["pub_sub_kms"]
}

pub_sub_kms = false {
    gc_issue["pub_sub_kms"]
}

pub_sub_kms_err = "Ensure GCP Pub/Sub topic is encrypted using a customer-managed encryption key" {
    gc_issue["pub_sub_kms"]
}

pub_sub_kms_metadata := {
    "Policy Code": "PR-GCP-CLD-PUB-001",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "Ensure GCP Pub/Sub topic is encrypted using a customer-managed encryption key",
    "Policy Description": "This policy identifies GCP Pub/Sub topics that are not encrypted using a customer-managed encryption key. It is a best practice to use customer-managed KMS Keys to encrypt your Pub/Sub topic. Customer-managed CMKs give you more flexibility, including the ability to create, rotate, disable, define access control for, and audit the encryption keys used to help protect your data.\n\nReference: https://cloud.google.com/pubsub/docs/encryption",
    "Resource Type": "pubsub.v1.topic",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/pubsub/docs/reference/rest/v1/projects.topics"
}


#
# PR-GCP-CLD-WAF-001
#

default waf_log4j_vulnerability = null

gc_issue["waf_log4j_vulnerability"] {
    rule := input.rule[_]
    match := rule.match[_]
    expr := match.expr[_]
    count([c | lower(input.rule[_].match[_].expr[_].expression) == "evaluatepreconfiguredexpr('cve-canary')"; c:=1]) == 0
}

waf_log4j_vulnerability {
    not gc_issue["waf_log4j_vulnerability"]
}

waf_log4j_vulnerability = false {
    gc_issue["waf_log4j_vulnerability"]
}

waf_log4j_vulnerability_err = "Ensure GCP Pub/Sub topic is encrypted using a customer-managed encryption key" {
    gc_issue["waf_log4j_vulnerability"]
}

waf_log4j_vulnerability_metadata := {
    "Policy Code": "PR-GCP-CLD-WAF-001",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "Ensure GCP Pub/Sub topic is encrypted using a customer-managed encryption key",
    "Policy Description": "This policy identifies GCP Pub/Sub topics that are not encrypted using a customer-managed encryption key. It is a best practice to use customer-managed KMS Keys to encrypt your Pub/Sub topic. Customer-managed CMKs give you more flexibility, including the ability to create, rotate, disable, define access control for, and audit the encryption keys used to help protect your data.\n\nReference: https://cloud.google.com/pubsub/docs/encryption",
    "Resource Type": "google_compute_security_policy",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/pubsub/docs/reference/rest/v1/projects.topics"
}
