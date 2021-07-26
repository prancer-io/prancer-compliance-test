package rule

# https://github.com/aws-controllers-k8s/sns-controller

#
# PR-AWS-0153-ACK
#

default sns_encrypt_key = null

aws_issue["sns_encrypt_key"] {
    resource := input.Resources[i]
    lower(resource.kind) == "topic"
    contains(lower(resource.spec.KmsMasterKeyId), "alias/aws/sns")
}

sns_encrypt_key {
    lower(input.Resources[i].Type) == "topic"
    not aws_issue["sns_encrypt_key"]
}

sns_encrypt_key = false {
    aws_issue["sns_encrypt_key"]
}

sns_encrypt_key_err = "AWS SNS topic encrypted using default KMS key instead of CMK" {
    aws_issue["sns_encrypt_key"]
}

sns_encrypt_key_metadata := {
    "Policy Code": "PR-AWS-0153-ACK",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "ACK",
    "Policy Title": "AWS SNS topic encrypted using default KMS key instead of CMK",
    "Policy Description": "This policy identifies Amazon Simple Notification Service (SNS) topics that are encrypted with the default AWS Key Management Service (KMS) keys. As a best practice, use Customer Master Keys (CMK) to encrypt the data in your SNS topics and ensure full control over your data.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sns-subscription.html"
}

#
# PR-AWS-0154-ACK
#

default sns_encrypt = null

aws_issue["sns_encrypt"] {
    resource := input.Resources[i]
    lower(resource.kind) == "topic"
    not resource.spec.KmsMasterKeyId
}

aws_issue["sns_encrypt"] {
    resource := input.Resources[i]
    lower(resource.kind) == "topic"
    count(resource.spec.KmsMasterKeyId) == 0
}

sns_encrypt {
    lower(input.Resources[i].Type) == "topic"
    not aws_issue["sns_encrypt"]
}

sns_encrypt = false {
    aws_issue["sns_encrypt"]
}

sns_encrypt_err = "AWS SNS topic with server-side encryption disabled" {
    aws_issue["sns_encrypt"]
}

sns_encrypt_metadata := {
    "Policy Code": "PR-AWS-0154-ACK",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "ACK",
    "Policy Title": "AWS SNS topic with server-side encryption disabled",
    "Policy Description": "This policy identifies Amazon Simple Notification Service (SNS) topics that have server-side encryption disabled. As a best practice, enable server-side encryption for at-rest encryption of message content published to SNS topics. When you publish a message, the SNS encrypts your message as soon as it receives it, and decrypts it just prior to delivery.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sns-subscription.html"
}
