package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sns-subscription.html
# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-sns-topic.html

#
# PR-AWS-0152-CFR
#

default sns_protocol = null

aws_attribute_absence["sns_protocol"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::sns::subscription"
    not resource.Properties.Protocol
}

aws_issue["sns_protocol"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::sns::subscription"
    lower(resource.Properties.Protocol) == "http"
}

sns_protocol {
    lower(input.Resources[i].Type) == "aws::sns::subscription"
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

sns_protocol_miss_err = "SNS attribute Protocol missing in the resource" {
    aws_attribute_absence["sns_protocol"]
}

sns_protocol_metadata := {
    "Policy Code": "PR-AWS-0152-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS SNS subscription is not configured with HTTPS",
    "Policy Description": "This policy identifies SNS subscriptions using HTTP instead of HTTPS as the delivery protocol in order to enforce SSL encryption for all subscription requests. It is strongly recommended use only HTTPS-based subscriptions by implementing secure SNS topic policies.",
    "Compliance": [],
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sns-subscription.html"
}

#
# PR-AWS-0153-CFR
#

default sns_encrypt_key = null

aws_issue["sns_encrypt_key"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::sns::topic"
    contains(lower(resource.Properties.KmsMasterKeyId), "alias/aws/sns")
}

sns_encrypt_key {
    lower(input.Resources[i].Type) == "aws::sns::topic"
    not aws_issue["sns_encrypt_key"]
}

sns_encrypt_key = false {
    aws_issue["sns_encrypt_key"]
}

sns_encrypt_key_err = "AWS SNS topic encrypted using default KMS key instead of CMK" {
    aws_issue["sns_encrypt_key"]
}

sns_encrypt_key_metadata := {
    "Policy Code": "PR-AWS-0153-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS SNS topic encrypted using default KMS key instead of CMK",
    "Policy Description": "This policy identifies Amazon Simple Notification Service (SNS) topics that are encrypted with the default AWS Key Management Service (KMS) keys. As a best practice, use Customer Master Keys (CMK) to encrypt the data in your SNS topics and ensure full control over your data.",
    "Compliance": [],
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sns-subscription.html"
}

#
# PR-AWS-0154-CFR
#

default sns_encrypt = null

aws_attribute_absence["sns_encrypt"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::sns::topic"
    not resource.Properties.KmsMasterKeyId
}

aws_issue["sns_encrypt"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::sns::topic"
    count(resource.Properties.KmsMasterKeyId) == 0
}

sns_encrypt {
    lower(input.Resources[i].Type) == "aws::sns::topic"
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

sns_encrypt_miss_err = "SNS attribute KmsMasterKeyId missing in the resource" {
    aws_attribute_absence["sns_encrypt"]
}

sns_encrypt_metadata := {
    "Policy Code": "PR-AWS-0154-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS SNS topic with server-side encryption disabled",
    "Policy Description": "This policy identifies Amazon Simple Notification Service (SNS) topics that have server-side encryption disabled. As a best practice, enable server-side encryption for at-rest encryption of message content published to SNS topics. When you publish a message, the SNS encrypts your message as soon as it receives it, and decrypts it just prior to delivery.",
    "Compliance": [],
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sns-subscription.html"
}
