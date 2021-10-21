package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-sqs-queues.html

#
# PR-AWS-0155-TRF
#

default sqs_deadletter = null

aws_issue["sqs_deadletter"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_sqs_queue"
    not resource.properties.redrive_policy.deadLetterTargetArn
}

sqs_deadletter {
    lower(input.resources[_].type) == "aws_sqs_queue"
    not aws_issue["sqs_deadletter"]
}

sqs_deadletter = false {
    aws_issue["sqs_deadletter"]
}

sqs_deadletter_err = "AWS SQS does not have a dead letter queue configured" {
    aws_issue["sqs_deadletter"]
}

sqs_deadletter_metadata := {
    "Policy Code": "PR-AWS-0155-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS SQS does not have a dead letter queue configured",
    "Policy Description": "This policy identifies AWS Simple Queue Services (SQS) which does not have dead letter queue configured. Dead letter queues are useful for debugging your application or messaging system because they let you isolate problematic messages to determine why their processing doesn't succeed.",
    "Resource Type": "aws_sqs_queue",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-sqs-queues.html"
}

#
# PR-AWS-0156-TRF
#

default sqs_encrypt_key = null

aws_issue["sqs_encrypt_key"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_sqs_queue"
    resource.properties.kms_master_key_id
    resource.properties.kms_master_key_id != null
    contains(lower(resource.properties.kms_master_key_id), "alias/aws/sqs")
}

sqs_encrypt_key {
    lower(input.resources[_].type) == "aws_sqs_queue"
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
} else = "SQS Queue attribute kms_master_key_id missing in the resource" {
    aws_attribute_absence["sqs_encrypt_key"]
}

sqs_encrypt_key_metadata := {
    "Policy Code": "PR-AWS-0156-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS SQS queue encryption using default KMS key instead of CMK",
    "Policy Description": "This policy identifies CloudFront web distributions which have a default SSL certificate to access CloudFront content. It is a best practice to use custom SSL Certificate to access CloudFront content. It gives you full control over the content data. custom SSL certificates also allow your users to access your content by using an alternate domain name. You can use a certificate stored in AWS Certificate Manager (ACM) or you can use a certificate stored in IAM.",
    "Resource Type": "aws_sqs_queue",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-sqs-queues.html"
}

#
# PR-AWS-0157-TRF
#

default sqs_encrypt = null

aws_attribute_absence["sqs_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_sqs_queue"
    not resource.properties.kms_master_key_id
}

aws_attribute_absence["sqs_encrypt"] {
	resource := input.resources[_]
	lower(resource.type) == "aws_sqs_queue"
	resource.properties.kms_master_key_id == null
}

aws_issue["sqs_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_sqs_queue"
    resource.properties.kms_master_key_id != null
    count(resource.properties.kms_master_key_id) == 0
}

sqs_encrypt {
    lower(input.resources[_].type) == "aws_sqs_queue"
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
} else = "SQS Queue attribute kms_master_key_id missing in the resource" {
    aws_attribute_absence["sqs_encrypt"]
}

sqs_encrypt_metadata := {
    "Policy Code": "PR-AWS-0157-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS SQS server side encryption not enabled",
    "Policy Description": "SSE lets you transmit sensitive data in encrypted queues. SSE protects the contents of messages in Amazon SQS queues using keys managed in the AWS Key Management Service (AWS KMS). SSE encrypts messages as soon as Amazon SQS receives them. The messages are stored in encrypted form and Amazon SQS decrypts messages only when they are sent to an authorized consumer.<br><br>SQS SSE and the AWS KMS security standards can help you meet encryption-related compliance requirements.",
    "Resource Type": "aws_sqs_queue",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-sqs-queues.html"
}
