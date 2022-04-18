package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sns-subscription.html
# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-sns-topic.html

#
# PR-AWS-CLD-SNS-001
#

default sns_protocol = true

sns_protocol = false {
    # lower(resource.Type) == "aws::sns::subscription"
    Subscriptions := input.Subscriptions[_]
    lower(Subscriptions.Protocol) == "http"
}

sns_protocol_err = "AWS SNS subscription is not configured with HTTPS" {
    not sns_protocol
}

sns_protocol_metadata := {
    "Policy Code": "PR-AWS-CLD-SNS-001",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS SNS subscription is not configured with HTTPS",
    "Policy Description": "This policy identifies SNS subscriptions using HTTP instead of HTTPS as the delivery protocol in order to enforce SSL encryption for all subscription requests. It is strongly recommended use only HTTPS-based subscriptions by implementing secure SNS topic policies.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sns-subscription.html"
}

#
# PR-AWS-CLD-SNS-002
#

default sns_encrypt_key = true

sns_encrypt_key = false {
    # lower(resource.Type) == "aws::sns::topic"
    contains(lower(input.Attributes.KmsMasterKeyId), "alias/aws/sns")
}

sns_encrypt_key_err = "AWS SNS topic encrypted using default KMS key instead of CMK" {
    not sns_encrypt_key
}

sns_encrypt_key_metadata := {
    "Policy Code": "PR-AWS-CLD-SNS-002",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS SNS topic encrypted using default KMS key instead of CMK",
    "Policy Description": "This policy identifies Amazon Simple Notification Service (SNS) topics that are encrypted with the default AWS Key Management Service (KMS) keys. As a best practice, use Customer Master Keys (CMK) to encrypt the data in your SNS topics and ensure full control over your data.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sns-subscription.html"
}

#
# PR-AWS-CLD-SNS-003
#

default sns_encrypt = true

sns_encrypt = false {
    # lower(resource.Type) == "aws::sns::topic"
    not input.Attributes.KmsMasterKeyId
}

sns_encrypt = false {
    # lower(resource.Type) == "aws::sns::topic"
    count(input.Attributes.KmsMasterKeyId) == 0
}

sns_encrypt_err = "AWS SNS topic with server-side encryption disabled" {
    not sns_encrypt
}

sns_encrypt_metadata := {
    "Policy Code": "PR-AWS-CLD-SNS-003",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS SNS topic with server-side encryption disabled",
    "Policy Description": "This policy identifies Amazon Simple Notification Service (SNS) topics that have server-side encryption disabled. As a best practice, enable server-side encryption for at-rest encryption of message content published to SNS topics. When you publish a message, the SNS encrypts your message as soon as it receives it, and decrypts it just prior to delivery.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sns-subscription.html"
}


#
# PR-AWS-CLD-SNS-004
#

default sns_policy_public = true

sns_policy_public = false {
    # lower(resource.Type) == "aws::sns::topicpolicy"
    policy := json.unmarshal(input.Attributes.Policy)
    statement := policy.Statement[_]
    lower(statement.Effect) == "allow"
    statement.Principal == "*"
}

sns_policy_public = false {
    # lower(resource.Type) == "aws::sns::topicpolicy"
    policy := json.unmarshal(input.Attributes.Policy)
    statement := policy.Statement[_]
    lower(statement.Effect) == "allow"
    statement.Principal.AWS == "*"
}

sns_policy_public = false {
    # lower(resource.Type) == "aws::sns::topicpolicy"
    policy := json.unmarshal(input.Attributes.Policy)
    statement := policy.Statement[_]
    lower(statement.Effect) == "allow"
    statement.Principal.AWS[_] = "*"
}

sns_policy_public_err = "Ensure SNS Topic policy is not publicly accessible" {
    not sns_policy_public
}

sns_policy_public_metadata := {
    "Policy Code": "PR-AWS-CLD-SNS-004",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure SNS Topic policy is not publicly accessible",
    "Policy Description": "Public SNS Topic potentially expose existing interfaces to unwanted 3rd parties that can tap into an existing data stream, resulting in data leak to an unwanted party.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-sns-policy.html"
}