package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sns-subscription.html
# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-sns-topic.html

#
# Id: 152
#

default sns_protocol = null

aws_attribute_absence["sns_protocol"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::sns::subscription"
    not resource.Properties.Protocol
}

aws_issue["sns_protocol"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::sns::subscription"
    lower(resource.Properties.Protocol) == "http"
}

sns_protocol {
    lower(input.resources[_].Type) == "aws::sns::subscription"
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

#
# Id: 153
#

default sns_encrypt_key = null

aws_issue["sns_encrypt_key"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::sns::topic"
    contains(lower(resource.Properties.KmsMasterKeyId), "alias/aws/sns")
}

sns_encrypt_key {
    lower(input.resources[_].Type) == "aws::sns::topic"
    not aws_issue["sns_encrypt_key"]
}

sns_encrypt_key = false {
    aws_issue["sns_encrypt_key"]
}

sns_encrypt_key_err = "AWS SNS topic encrypted using default KMS key instead of CMK" {
    aws_issue["sns_encrypt_key"]
}

#
# Id: 154
#

default sns_encrypt = null

aws_attribute_absence["sns_encrypt"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::sns::topic"
    not resource.Properties.KmsMasterKeyId
}

aws_issue["sns_encrypt"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::sns::topic"
    count(resource.Properties.KmsMasterKeyId) == 0
}

sns_encrypt {
    lower(input.resources[_].Type) == "aws::sns::topic"
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
