package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-sqs-queues.html

#
# PR-AWS-CLD-SQS-001
#

default sqs_deadletter = true

sqs_deadletter = false {
    # lower(resource.Type) == "aws::sqs::queue"
    RedrivePolicy := json.unmarshal(input.RedrivePolicy)
    not RedrivePolicy.deadLetterTargetArn
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
    policy := json.unmarshal(input.Attributes.Policy)
    statement := policy.Statement[j]
    lower(statement.Effect) == "allow"
    statement.Principal == "*"
}

sqs_policy_public = false {
    # lower(resource.Type) == "aws::sqs::queuepolicy"
    policy := json.unmarshal(input.Attributes.Policy)
    statement := policy.Statement[j]
    lower(statement.Effect) == "allow"
    statement.Principal.AWS == "*"
}

sqs_policy_public = false {
    # lower(resource.Type) == "aws::sqs::queuepolicy"
    policy := json.unmarshal(input.Attributes.Policy)
    statement := policy.Statement[j]
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

default sqs_policy_action = true

sqs_policy_action = false {
    # lower(resource.Type) == "aws::sqs::queuepolicy"
    policy := json.unmarshal(input.Attributes.Policy)
    statement := policy.Statement[j]
    lower(statement.Effect) == "allow"
    statement.Action == "sqs:*"
}

sqs_policy_action = false {
    # lower(resource.Type) == "aws::sqs::queuepolicy"
    policy := json.unmarshal(input.Attributes.Policy)
    statement := policy.Statement[j]
    lower(statement.Effect) == "allow"
    statement.Action[k] == "sqs:*"
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


#
# PR-AWS-CLD-SQS-006
# aws::sqs::queuepolicy

default sqs_not_overly_permissive = true

sqs_not_overly_permissive = false {
    policy := json.unmarshal(input.Attributes.Policy)
    statement := policy.Statement[j]
    lower(statement.Effect) == "allow"
    startswith(lower(statement.Action), "sqs:")
    not statement.Condition
}

sqs_not_overly_permissive = false {
    policy := json.unmarshal(input.Attributes.Policy)
    statement := policy.Statement[j]
    lower(statement.Effect) == "allow"
    startswith(lower(statement.Action[k]), "sqs:")
    not statement.Condition
}

sqs_not_overly_permissive_err = "Ensure AWS SQS queue access policy is not overly permissive." {
    not sqs_not_overly_permissive
}

sqs_not_overly_permissive_metadata := {
    "Policy Code": "PR-AWS-CLD-SQS-006",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS SQS queue access policy is not overly permissive.",
    "Policy Description": "It identifies Simple Queue Service (SQS) queues that have an overly permissive access policy. It is highly recommended to have the least privileged access policy to protect the SQS queue from data leakage and unauthorized access. For more details: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-basic-examples-of-sqs-policies.html",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sqs-queuepolicy.html#cfn-sqs-queuepolicy-policy"
}

#
# PR-AWS-CLD-SQS-007
# aws::sqs::queuepolicy

default sqs_accessible_via_specific_vpc = true

sqs_accessible_via_specific_vpc = false {
    policy := json.unmarshal(input.Attributes.Policy)
    statement := policy.Statement[j]
    not contains(lower(statement.Condition.StringEquals), "aws:sourcevpce")
}

sqs_accessible_via_specific_vpc_err = "Ensure SQS is only accessible via specific VPCe service." {
    not sqs_accessible_via_specific_vpc
}

sqs_accessible_via_specific_vpc_metadata := {
    "Policy Code": "PR-AWS-CLD-SQS-007",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure SQS is only accessible via specific VPCe service.",
    "Policy Description": "It checks if SQS to other AWS services communication is managed by VPC endpoint and polcicies attached to it",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sqs-queuepolicy.html#cfn-sqs-queuepolicy-policy"
}


#
# PR-AWS-CLD-SQS-008
# aws::sqs::queuepolicy

default sqs_encrypted_in_transit = true

sqs_encrypted_in_transit = false {
    policy := json.unmarshal(input.Attributes.Policy)
    statement := policy.Statement[j]
    lower(statement.Effect) == "allow"
    statement.Principal == "*"
    not statement.Condition.Bool["aws:SecureTransport"]
}

sqs_encrypted_in_transit = false {
    policy := json.unmarshal(input.Attributes.Policy)
    statement := policy.Statement[j]
    lower(statement.Effect) == "allow"
    statement.Principal.AWS == "*"
    not statement.Condition.Bool["aws:SecureTransport"]
}

sqs_encrypted_in_transit = false {
    policy := json.unmarshal(input.Attributes.Policy)
    statement := policy.Statement[j]
    lower(statement.Effect) == "allow"
    statement.Principal.AWS[_] = "*"
    not statement.Condition.Bool["aws:SecureTransport"]
}

sqs_encrypted_in_transit = false {
    policy := json.unmarshal(input.Attributes.Policy)
    statement := policy.Statement[j]
    lower(statement.Effect) == "allow"
    statement.Principal == "*"
    lower(statement.Condition.Bool["aws:SecureTransport"]) == "false"
}

sqs_encrypted_in_transit = false {
    policy := json.unmarshal(input.Attributes.Policy)
    statement := policy.Statement[j]
    lower(statement.Effect) == "allow"
    statement.Principal.AWS == "*"
    lower(statement.Condition.Bool["aws:SecureTransport"]) == "false"
}

sqs_encrypted_in_transit = false {
    policy := json.unmarshal(input.Attributes.Policy)
    statement := policy.Statement[j]
    lower(statement.Effect) == "allow"
    statement.Principal.AWS[_] = "*"
    lower(statement.Condition.Bool["aws:SecureTransport"]) == "false"
}

sqs_encrypted_in_transit = false {
    policy := json.unmarshal(input.Attributes.Policy)
    statement := policy.Statement[j]
    lower(statement.Effect) == "deny"
    statement.Principal == "*"
    lower(statement.Condition.Bool["aws:SecureTransport"]) == "true"
}

sqs_encrypted_in_transit = false {
    policy := json.unmarshal(input.Attributes.Policy)
    statement := policy.Statement[j]
    lower(statement.Effect) == "deny"
    statement.Principal.AWS == "*"
    lower(statement.Condition.Bool["aws:SecureTransport"]) == "true"
}

sqs_encrypted_in_transit = false {
    policy := json.unmarshal(input.Attributes.Policy)
    statement := policy.Statement[j]
    lower(statement.Effect) == "deny"
    statement.Principal.AWS[_] = "*"
    lower(statement.Condition.Bool["aws:SecureTransport"]) == "true"
}

sqs_encrypted_in_transit_err = "Ensure SQS data is encrypted in Transit using SSL/TLS." {
    not sqs_encrypted_in_transit
}

sqs_encrypted_in_transit_metadata := {
    "Policy Code": "PR-AWS-CLD-SQS-008",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure SQS data is encrypted in Transit using SSL/TLS.",
    "Policy Description": "It checks if data in transit is encrypted for SQS service.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sqs-queuepolicy.html#cfn-sqs-queuepolicy-policy"
}