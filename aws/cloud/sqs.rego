package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-sqs-queues.html

#
# PR-AWS-CLD-SQS-001
#

default sqs_deadletter = true

sqs_deadletter = false {
    # lower(resource.Type) == "aws::sqs::queue"
    not input.RedrivePolicy.deadLetterTargetArn
}

sqs_deadletter_err = "AWS SQS does not have a dead letter queue configured" {
    not sqs_deadletter
}

sqs_deadletter_metadata := {
    "Policy Code": "PR-AWS-CLD-SQS-001",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS SQS does not have a dead letter queue configured",
    "Policy Description": "This policy identifies AWS Simple Queue Services (SQS) which does not have dead letter queue configured. Dead letter queues are useful for debugging your application or messaging system because they let you isolate problematic messages to determine why their processing doesn't succeed.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-sqs-queues.html"
}

#
# PR-AWS-CLD-SQS-002
#

default sqs_encrypt_key = true


sqs_encrypt_key = false {
    # lower(resource.Type) == "aws::sqs::queue"
    input.KmsMasterKeyId
    contains(lower(input.KmsMasterKeyId), "alias/aws/sqs")
}

sqs_encrypt_key_err = "AWS SQS queue encryption using default KMS key instead of CMK" {
    not sqs_encrypt_key
}

sqs_encrypt_key_metadata := {
    "Policy Code": "PR-AWS-CLD-SQS-002",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS SQS queue encryption using default KMS key instead of CMK",
    "Policy Description": "This policy identifies CloudFront web distributions which have a default SSL certificate to access CloudFront content. It is a best practice to use custom SSL Certificate to access CloudFront content. It gives you full control over the content data. custom SSL certificates also allow your users to access your content by using an alternate domain name. You can use a certificate stored in AWS Certificate Manager (ACM) or you can use a certificate stored in IAM.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-sqs-queues.html"
}

#
# PR-AWS-CLD-SQS-003
#

default sqs_encrypt = true

sqs_encrypt = false {
    # lower(resource.Type) == "aws::sqs::queue"
    not input.KmsMasterKeyId
}

sqs_encrypt = false {
    # lower(resource.Type) == "aws::sqs::queue"
    count(input.KmsMasterKeyId) == 0
}

sqs_encrypt_err = "AWS SQS server side encryption not enabled" {
    not sqs_encrypt
}

sqs_encrypt_metadata := {
    "Policy Code": "PR-AWS-CLD-SQS-003",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS SQS server side encryption not enabled",
    "Policy Description": "SSE lets you transmit sensitive data in encrypted queues. SSE protects the contents of messages in Amazon SQS queues using keys managed in the AWS Key Management Service (AWS KMS). SSE encrypts messages as soon as Amazon SQS receives them. The messages are stored in encrypted form and Amazon SQS decrypts messages only when they are sent to an authorized consumer.<br><br>SQS SSE and the AWS KMS security standards can help you meet encryption-related compliance requirements.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-sqs-queues.html"
}


#
# PR-AWS-CLD-SQS-004
#

default sqs_policy_public = true

sqs_policy_public = false {
    # lower(resource.Type) == "aws::sqs::queuepolicy"
    statement := input.policy.Statement[j]
    lower(statement.Effect) == "allow"
    statement.Principal == "*"
}

sqs_policy_public = false {
    # lower(resource.Type) == "aws::sqs::queuepolicy"
    statement := input.policy.Statement[j]
    lower(statement.Effect) == "allow"
    statement.Principal.AWS == "*"
}

sqs_policy_public = false {
    # lower(resource.Type) == "aws::sqs::queuepolicy"
    statement := input.policy.Statement[j]
    lower(statement.Effect) == "allow"
    statement.Principal.AWS[k] = "*"
}

sqs_policy_public_err = "Ensure SQS queue policy is not publicly accessible" {
    not sqs_policy_public
}

sqs_policy_public_metadata := {
    "Policy Code": "PR-AWS-CLD-SQS-004",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure SQS queue policy is not publicly accessible",
    "Policy Description": "Public SQS queues potentially expose existing interfaces to unwanted 3rd parties that can tap into an existing data stream, resulting in data leak to an unwanted party.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sqs-queuepolicy.html#cfn-sqs-queuepolicy-policy"
}


#
# PR-AWS-CLD-SQS-005
#

default sqs_policy_action = null

sqs_policy_action = false {
    # lower(resource.Type) == "aws::sqs::queuepolicy"
    statement := input.policy.Statement[j]
    lower(statement.Effect) == "allow"
    statement.Action == "*"
}

sqs_policy_action = false {
    # lower(resource.Type) == "aws::sqs::queuepolicy"
    statement := input.policy.Statement[j]
    lower(statement.Effect) == "allow"
    statement.Action[k] == "*"
}

sqs_policy_action_err = "Ensure SQS policy documents do not allow all actions" {
    not sqs_policy_action
}

sqs_policy_action_metadata := {
    "Policy Code": "PR-AWS-CLD-SQS-005",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure SQS policy documents do not allow all actions",
    "Policy Description": "This level of access could potentially grant unwanted and unregulated access to anyone given this policy document setting. We recommend you to write a refined policy describing the specific action allowed or required by the specific policy holder",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sqs-queuepolicy.html#cfn-sqs-queuepolicy-policy"
}