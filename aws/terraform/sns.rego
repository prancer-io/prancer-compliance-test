package rule


#
# PR-AWS-TRF-SNS-001
#

default sns_protocol = null

aws_attribute_absence["sns_protocol"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_sns_topic_subscription"
    not resource.properties.protocol
}

source_path[{"sns_protocol": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_sns_topic_subscription"
    not resource.properties.protocol

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "protocol"]
        ],
    }
}

aws_issue["sns_protocol"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_sns_topic_subscription"
    lower(resource.properties.protocol) == "http"
}

source_path[{"sns_protocol": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_sns_topic_subscription"
    lower(resource.properties.protocol) == "http"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "protocol"]
        ],
    }
}

sns_protocol {
    lower(input.resources[i].type) == "aws_sns_topic_subscription"
    not aws_issue["sns_protocol"]
    not aws_attribute_absence["sns_protocol"]
}

sns_protocol = false {
    aws_issue["sns_protocol"]
}

sns_protocol = false {
    aws_attribute_absence["sns_protocol"]
}

sns_protocol_err = "AWS SNS subscription is not configured with HTTPS" {
    aws_issue["sns_protocol"]
} else = "SNS attribute protocol missing in the resource" {
    aws_attribute_absence["sns_protocol"]
}

sns_protocol_metadata := {
    "Policy Code": "PR-AWS-TRF-SNS-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS SNS subscription is not configured with HTTPS",
    "Policy Description": "This policy identifies SNS subscriptions using HTTP instead of HTTPS as the delivery protocol in order to enforce SSL encryption for all subscription requests. It is strongly recommended use only HTTPS-based subscriptions by implementing secure SNS topic policies.",
    "Resource Type": "aws_sns_topic",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic"
}

#
# PR-AWS-TRF-SNS-002
#

default sns_encrypt_key = null

aws_issue["sns_encrypt_key"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_sns_topic"
    resource.properties.kms_master_key_id != null
    contains(lower(resource.properties.kms_master_key_id), "alias/aws/sns")
}

source_path[{"sns_encrypt_key": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_sns_topic"
    resource.properties.kms_master_key_id != null
    contains(lower(resource.properties.kms_master_key_id), "alias/aws/sns")

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "kms_master_key_id"]
        ],
    }
}

sns_encrypt_key {
    lower(input.resources[i].type) == "aws_sns_topic"
    not aws_issue["sns_encrypt_key"]
}

sns_encrypt_key = false {
    aws_issue["sns_encrypt_key"]
}

sns_encrypt_key_err = "AWS SNS topic encrypted using default KMS key instead of CMK" {
    aws_issue["sns_encrypt_key"]
}

sns_encrypt_key_metadata := {
    "Policy Code": "PR-AWS-TRF-SNS-002",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS SNS topic encrypted using default KMS key instead of CMK",
    "Policy Description": "This policy identifies Amazon Simple Notification Service (SNS) topics that are encrypted with the default AWS Key Management Service (KMS) keys. As a best practice, use Customer Master Keys (CMK) to encrypt the data in your SNS topics and ensure full control over your data.",
    "Resource Type": "aws_sns_topic",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic"
}

#
# PR-AWS-TRF-SNS-003
#

default sns_encrypt = null

aws_attribute_absence["sns_encrypt"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_sns_topic"
    not resource.properties.kms_master_key_id
}

source_path[{"sns_encrypt": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_sns_topic"
    not resource.properties.kms_master_key_id

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "kms_master_key_id"]
        ],
    }
}

aws_issue["sns_encrypt"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_sns_topic"
    resource.properties.kms_master_key_id != null
    count(resource.properties.kms_master_key_id) == 0
}

source_path[{"sns_encrypt": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_sns_topic"
    resource.properties.kms_master_key_id != null
    count(resource.properties.kms_master_key_id) == 0

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "kms_master_key_id"]
        ],
    }
}

sns_encrypt {
    lower(input.resources[i].type) == "aws_sns_topic"
    not aws_attribute_absence["sns_encrypt"]
    not aws_issue["sns_encrypt"]
}

sns_encrypt = false {
    aws_issue["sns_encrypt"]
}

sns_encrypt = false {
    aws_attribute_absence["sns_encrypt"]
}

sns_encrypt_err = "AWS SNS topic with server-side encryption disabled" {
    aws_issue["sns_encrypt"]
} else = "SNS attribute kms_master_key_id missing in the resource" {
    aws_attribute_absence["sns_encrypt"]
}

sns_encrypt_metadata := {
    "Policy Code": "PR-AWS-TRF-SNS-003",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS SNS topic with server-side encryption disabled",
    "Policy Description": "This policy identifies Amazon Simple Notification Service (SNS) topics that have server-side encryption disabled. As a best practice, enable server-side encryption for at-rest encryption of message content published to SNS topics. When you publish a message, the SNS encrypts your message as soon as it receives it, and decrypts it just prior to delivery.",
    "Resource Type": "aws_sns_topic",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic"
}

#
# PR-AWS-TRF-SNS-004
#

default sns_policy_public = null

aws_issue["sns_policy_public"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_sns_topic_policy"
    statement := resource.properties.policy.Statement[_]
    lower(statement.Effect) == "allow"
    statement.Principal == "*"
}

aws_issue["sns_policy_public"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_sns_topic_policy"
    statement := resource.properties.policy.Statement[_]
    lower(statement.Effect) == "allow"
    statement.Principal.AWS == "*"
}

aws_issue["sns_policy_public"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_sns_topic_policy"
    statement := resource.properties.policy.Statement[_]
    lower(statement.Effect) == "allow"
    statement.Principal.AWS[_] = "*"
}


sns_policy_public {
    lower(input.resources[i].type) == "aws_sns_topic_policy"
    not aws_issue["sns_policy_public"]
}

sns_policy_public = false {
    aws_issue["sns_policy_public"]
}

sns_policy_public_err = "Ensure SNS Topic policy is not publicly accessible" {
    aws_issue["sns_policy_public"]
}

sns_policy_public_metadata := {
    "Policy Code": "PR-AWS-TRF-SNS-004",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure SNS Topic policy is not publicly accessible",
    "Policy Description": "Public SNS Topic potentially expose existing interfaces to unwanted 3rd parties that can tap into an existing data stream, resulting in data leak to an unwanted party.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic_policy"
}