package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sns-subscription.html
# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-sns-topic.html

#
# PR-AWS-0152-TRF
#

default sns_protocol = null

aws_attribute_absence["sns_protocol"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_sns_topic_subscription"
    not resource.properties.protocol
}

aws_issue["sns_protocol"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_sns_topic_subscription"
    lower(resource.properties.protocol) == "http"
}

sns_protocol {
    lower(input.resources[_].type) == "aws_sns_topic_subscription"
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
}

sns_protocol_miss_err = "SNS attribute protocol missing in the resource" {
    aws_attribute_absence["sns_protocol"]
}

sns_protocol_metadata := {
    "Policy Code": "PR-AWS-0152-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS SNS subscription is not configured with HTTPS",
    "Policy Description": "This policy identifies SNS subscriptions using HTTP instead of HTTPS as the delivery protocol in order to enforce SSL encryption for all subscription requests. It is strongly recommended use only HTTPS-based subscriptions by implementing secure SNS topic policies.",
    "Resource Type": "aws_sns_topic",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sns-subscription.html"
}

#
# PR-AWS-0153-TRF
#

default sns_encrypt_key = null

aws_issue["sns_encrypt_key"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_sns_topic"
    contains(lower(resource.properties.kms_master_key_id), "alias/aws/sns")
}

sns_encrypt_key {
    lower(input.resources[_].type) == "aws_sns_topic"
    not aws_issue["sns_encrypt_key"]
}

sns_encrypt_key = false {
    aws_issue["sns_encrypt_key"]
}

sns_encrypt_key_err = "AWS SNS topic encrypted using default KMS key instead of CMK" {
    aws_issue["sns_encrypt_key"]
}

sns_encrypt_key_metadata := {
    "Policy Code": "PR-AWS-0153-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS SNS topic encrypted using default KMS key instead of CMK",
    "Policy Description": "This policy identifies Amazon Simple Notification Service (SNS) topics that are encrypted with the default AWS Key Management Service (KMS) keys. As a best practice, use Customer Master Keys (CMK) to encrypt the data in your SNS topics and ensure full control over your data.",
    "Resource Type": "aws_sns_topic",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sns-subscription.html"
}

#
# PR-AWS-0154-TRF
#

default sns_encrypt = null

aws_attribute_absence["sns_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_sns_topic"
    not resource.properties.kms_master_key_id
}

aws_issue["sns_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_sns_topic"
    count(resource.properties.kms_master_key_id) == 0
}

sns_encrypt {
    lower(input.resources[_].type) == "aws_sns_topic"
    not aws_issue["sns_encrypt"]
    not aws_attribute_absence["sns_encrypt"]
}

sns_encrypt = false {
    aws_issue["sns_encrypt"]
}

sns_encrypt = false {
    aws_attribute_absence["sns_encrypt"]
}

sns_encrypt_err = "AWS SNS topic with server-side encryption disabled" {
    aws_issue["sns_encrypt"]
}

sns_encrypt_miss_err = "SNS attribute kms_master_key_id missing in the resource" {
    aws_attribute_absence["sns_encrypt"]
}

sns_encrypt_metadata := {
    "Policy Code": "PR-AWS-0154-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS SNS topic with server-side encryption disabled",
    "Policy Description": "This policy identifies Amazon Simple Notification Service (SNS) topics that have server-side encryption disabled. As a best practice, enable server-side encryption for at-rest encryption of message content published to SNS topics. When you publish a message, the SNS encrypts your message as soon as it receives it, and decrypts it just prior to delivery.",
    "Resource Type": "aws_sns_topic",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sns-subscription.html"
}
