package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-sqs-queues.html

#
# PR-AWS-0155-CFR
#

default sqs_deadletter = null

aws_issue["sqs_deadletter"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::sqs::queue"
    not resource.Properties.RedrivePolicy.deadLetterTargetArn
}

sqs_deadletter {
    lower(input.Resources[i].Type) == "aws::sqs::queue"
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

sqs_deadletter_metadata := {
    "Policy Code": "PR-AWS-0155-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS SQS does not have a dead letter queue configured",
    "Policy Description": "This policy identifies AWS Simple Queue Services (SQS) which does not have dead letter queue configured. Dead letter queues are useful for debugging your application or messaging system because they let you isolate problematic messages to determine why their processing doesn't succeed.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-sqs-queues.html"
}

#
# PR-AWS-0156-CFR
#

default sqs_encrypt_key = null

aws_attribute_absence["sqs_encrypt_key"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::sqs::queue"
    not resource.Properties.KmsMasterKeyId
}

aws_issue["sqs_encrypt_key"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::sqs::queue"
    contains(lower(resource.Properties.KmsMasterKeyId), "alias/aws/sqs")
}

sqs_encrypt_key {
    lower(input.Resources[i].Type) == "aws::sqs::queue"
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

sqs_encrypt_key_metadata := {
    "Policy Code": "PR-AWS-0156-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS SQS queue encryption using default KMS key instead of CMK",
    "Policy Description": "This policy identifies CloudFront web distributions which have a default SSL certificate to access CloudFront content. It is a best practice to use custom SSL Certificate to access CloudFront content. It gives you full control over the content data. custom SSL certificates also allow your users to access your content by using an alternate domain name. You can use a certificate stored in AWS Certificate Manager (ACM) or you can use a certificate stored in IAM.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-sqs-queues.html"
}

#
# PR-AWS-0157-CFR
#

default sqs_encrypt = null

aws_attribute_absence["sqs_encrypt"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::sqs::queue"
    not resource.Properties.KmsMasterKeyId
}

aws_issue["sqs_encrypt"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::sqs::queue"
    count(resource.Properties.KmsMasterKeyId) == 0
}

sqs_encrypt {
    lower(input.Resources[i].Type) == "aws::sqs::queue"
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

sqs_encrypt_metadata := {
    "Policy Code": "PR-AWS-0157-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS SQS server side encryption not enabled",
    "Policy Description": "SSE lets you transmit sensitive data in encrypted queues. SSE protects the contents of messages in Amazon SQS queues using keys managed in the AWS Key Management Service (AWS KMS). SSE encrypts messages as soon as Amazon SQS receives them. The messages are stored in encrypted form and Amazon SQS decrypts messages only when they are sent to an authorized consumer._x005F_x000D_ _x005F_x000D_ SQS SSE and the AWS KMS security standards can help you meet encryption-related compliance requirements.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-sqs-queues.html"
}
