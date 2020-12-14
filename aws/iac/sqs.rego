package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-sqs-queues.html

#
# PR-AWS-0155-CFR
#

default sqs_deadletter = null

aws_issue["sqs_deadletter"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::sqs::queue"
    not resource.Properties.RedrivePolicy.deadLetterTargetArn
}

sqs_deadletter {
    lower(input.resources[_].Type) == "aws::sqs::queue"
    not aws_issue["sqs_deadletter"]
    not aws_attribute_absence["sqs_deadletter"]
}

sqs_deadletter = false {
    aws_issue["sqs_deadletter"]
}

sqs_deadletter = false {
    aws_attribute_absence["sqs_deadletter"]
}

sqs_deadletter_err = "AWS SQS does not have a dead letter queue configured" {
    aws_issue["sqs_deadletter"]
}

#
# PR-AWS-0156-CFR
#

default sqs_encrypt_key = null

aws_attribute_absence["sqs_encrypt_key"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::sqs::queue"
    not resource.Properties.KmsMasterKeyId
}

aws_issue["sqs_encrypt_key"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::sqs::queue"
    contains(lower(resource.Properties.KmsMasterKeyId), "alias/aws/sqs")
}

sqs_encrypt_key {
    lower(input.resources[_].Type) == "aws::sqs::queue"
    not aws_issue["sqs_encrypt_key"]
    not aws_attribute_absence["sqs_encrypt_key"]
}

sqs_encrypt_key = false {
    aws_issue["sqs_encrypt_key"]
}

sqs_encrypt_key = false {
    aws_attribute_absence["sqs_encrypt_key"]
}

sqs_encrypt_key_err = "AWS SQS queue encryption using default KMS key instead of CMK" {
    aws_issue["sqs_encrypt_key"]
}

sqs_encrypt_key_miss_err = "SQS Queue attribute KmsMasterKeyId missing in the resource" {
    aws_attribute_absence["sqs_encrypt_key"]
}

#
# PR-AWS-0157-CFR
#

default sqs_encrypt = null

aws_attribute_absence["sqs_encrypt"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::sqs::queue"
    not resource.Properties.KmsMasterKeyId
}

aws_issue["sqs_encrypt"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::sqs::queue"
    count(resource.Properties.KmsMasterKeyId) == 0
}

sqs_encrypt {
    lower(input.resources[_].Type) == "aws::sqs::queue"
    not aws_issue["sqs_encrypt"]
    not aws_attribute_absence["sqs_encrypt"]
}

sqs_encrypt = false {
    aws_issue["sqs_encrypt"]
}

sqs_encrypt = false {
    aws_attribute_absence["sqs_encrypt"]
}

sqs_encrypt_err = "AWS SQS server side encryption not enabled" {
    aws_issue["sqs_encrypt"]
}

sqs_encrypt_miss_err = "SQS Queue attribute KmsMasterKeyId missing in the resource" {
    aws_attribute_absence["sqs_encrypt"]
}
