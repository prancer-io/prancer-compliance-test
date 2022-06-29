package rule
default metadata = {}

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sns-subscription.html
# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-sns-topic.html

#
# PR-AWS-CFR-SNS-001
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

source_path[{"sns_protocol": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::sns::subscription"
    not resource.Properties.Protocol
    metadata := {
        "resource_path": [["Resources", i, "Properties", "Protocol"]],
    }
}

source_path[{"sns_protocol": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::sns::subscription"
    lower(resource.Properties.Protocol) == "http"
    metadata := {
        "resource_path": [["Resources", i, "Properties", "Protocol"]],
    }
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
    "Policy Code": "PR-AWS-CFR-SNS-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS SNS subscription is not configured with HTTPS",
    "Policy Description": "This policy identifies SNS subscriptions using HTTP instead of HTTPS as the delivery protocol in order to enforce SSL encryption for all subscription requests. It is strongly recommended use only HTTPS-based subscriptions by implementing secure SNS topic policies.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sns-subscription.html"
}

#
# PR-AWS-CFR-SNS-002
#

default sns_encrypt_key = null

aws_issue["sns_encrypt_key"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::sns::topic"
    contains(lower(resource.Properties.KmsMasterKeyId), "alias/aws/sns")
}

source_path[{"sns_encrypt_key": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::sns::topic"
    contains(lower(resource.Properties.KmsMasterKeyId), "alias/aws/sns")
    metadata := {
        "resource_path": [["Resources", i, "Properties", "KmsMasterKeyId"]],
    }
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
    "Policy Code": "PR-AWS-CFR-SNS-002",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS SNS topic encrypted using default KMS key instead of CMK",
    "Policy Description": "This policy identifies Amazon Simple Notification Service (SNS) topics that are encrypted with the default AWS Key Management Service (KMS) keys. As a best practice, use Customer Master Keys (CMK) to encrypt the data in your SNS topics and ensure full control over your data.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sns-subscription.html"
}

#
# PR-AWS-CFR-SNS-003
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

source_path[{"sns_encrypt": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::sns::topic"
    not resource.Properties.KmsMasterKeyId
    metadata := {
        "resource_path": [["Resources", i, "Properties", "KmsMasterKeyId"]],
    }
}

source_path[{"sns_encrypt": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::sns::topic"
    count(resource.Properties.KmsMasterKeyId) == 0
    metadata := {
        "resource_path": [["Resources", i, "Properties", "KmsMasterKeyId"]],
    }
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
    "Policy Code": "PR-AWS-CFR-SNS-003",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS SNS topic with server-side encryption disabled",
    "Policy Description": "This policy identifies Amazon Simple Notification Service (SNS) topics that have server-side encryption disabled. As a best practice, enable server-side encryption for at-rest encryption of message content published to SNS topics. When you publish a message, the SNS encrypts your message as soon as it receives it, and decrypts it just prior to delivery.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sns-subscription.html"
}


#
# PR-AWS-CFR-SNS-004
#

default sns_policy_public = null

aws_issue["sns_policy_public"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::sns::topicpolicy"
    statement := resource.Properties.PolicyDocument.Statement[_]
    lower(statement.Effect) == "allow"
    statement.Principal == "*"
}

aws_issue["sns_policy_public"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::sns::topicpolicy"
    statement := resource.Properties.PolicyDocument.Statement[_]
    lower(statement.Effect) == "allow"
    statement.Principal.AWS == "*"
}

aws_issue["sns_policy_public"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::sns::topicpolicy"
    statement := resource.Properties.PolicyDocument.Statement[_]
    lower(statement.Effect) == "allow"
    statement.Principal.AWS[_] = "*"
}


sns_policy_public {
    lower(input.Resources[i].Type) == "aws::sns::topicpolicy"
    not aws_issue["sns_policy_public"]
}

sns_policy_public = false {
    aws_issue["sns_policy_public"]
}

sns_policy_public_err = "Ensure SNS Topic policy is not publicly accessible" {
    aws_issue["sns_policy_public"]
}

sns_policy_public_metadata := {
    "Policy Code": "PR-AWS-CFR-SNS-004",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure SNS Topic policy is not publicly accessible",
    "Policy Description": "Public SNS Topic potentially expose existing interfaces to unwanted 3rd parties that can tap into an existing data stream, resulting in data leak to an unwanted party.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-sns-policy.html"
}


#
# PR-AWS-CFR-SNS-005
#

default sns_not_unauthorized_access = null

aws_issue["sns_not_unauthorized_access"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::sns::topicpolicy"
    policy := json.unmarshal(resource.Properties.PolicyDocument)
    statement:= policy.Statement[_]
    lower(statement.Effect) == "allow"
    statement.Principal == "*"
    not statement.Condition
}

aws_issue["sns_not_unauthorized_access"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::sns::topicpolicy"
    policy := json.unmarshal(resource.Properties.PolicyDocument)
    statement:= policy.Statement[_]
    lower(statement.Effect) == "allow"
    statement.Principal.AWS == "*"
    not statement.Condition
}

aws_issue["sns_not_unauthorized_access"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::sns::topicpolicy"
    policy := json.unmarshal(resource.Properties.PolicyDocument)
    statement:= policy.Statement[_]
    lower(statement.Effect) == "allow"
    statement.Principal.AWS[_] = "*"
    not statement.Condition
}


sns_not_unauthorized_access {
    lower(input.Resources[i].Type) == "aws::sns::topicpolicy"
    not aws_issue["sns_not_unauthorized_access"]
}

sns_not_unauthorized_access = false {
    aws_issue["sns_not_unauthorized_access"]
}

sns_not_unauthorized_access_err = "Ensure AWS SNS topic is not exposed to unauthorized access." {
    aws_issue["sns_not_unauthorized_access"]
}

sns_not_unauthorized_access_metadata := {
    "Policy Code": "PR-AWS-CFR-SNS-005",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure AWS SNS topic is not exposed to unauthorized access.",
    "Policy Description": "It identifies AWS SNS topics that are exposed to unauthorized access. Amazon Simple Notification Service (Amazon SNS) is a web service that coordinates and manages the delivery or sending of messages to subscribing endpoints or clients. To protect these messages from attackers and unauthorized accesses, permissions should be given to only authorized users. For more details: https://docs.aws.amazon.com/sns/latest/dg/sns-security-best-practices.html#ensure-topics-not-publicly-accessible",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-sns-policy.html"
}


#
# PR-AWS-CFR-SNS-006
#

default sns_permissive_for_publishing = null

aws_issue["sns_permissive_for_publishing"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::sns::topicpolicy"
    policy := json.unmarshal(resource.Properties.PolicyDocument)
    statement:= policy.Statement[_]
    lower(statement.Effect) == "allow"
    statement.Principal == "*"
    contains(lower(statement.Action[_]), "sns:publish")
    not statement.Condition
}

aws_issue["sns_permissive_for_publishing"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::sns::topicpolicy"
    policy := json.unmarshal(resource.Properties.PolicyDocument)
    statement:= policy.Statement[_]
    lower(statement.Effect) == "allow"
    statement.Principal.AWS == "*"
    contains(lower(statement.Action[_]), "sns:publish")
    not statement.Condition
}

aws_issue["sns_permissive_for_publishing"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::sns::topicpolicy"
    policy := json.unmarshal(resource.Properties.PolicyDocument)
    statement:= policy.Statement[_]
    lower(statement.Effect) == "allow"
    statement.Principal.AWS[_] = "*"
    contains(lower(statement.Action[_]), "sns:publish")
    not statement.Condition
}


sns_permissive_for_publishing {
    lower(input.Resources[i].Type) == "aws::sns::topicpolicy"
    not aws_issue["sns_permissive_for_publishing"]
}

sns_permissive_for_publishing = false {
    aws_issue["sns_permissive_for_publishing"]
}

sns_permissive_for_publishing_err = "Ensure AWS SNS topic policy is not overly permissive for publishing." {
    aws_issue["sns_permissive_for_publishing"]
}

sns_permissive_for_publishing_metadata := {
    "Policy Code": "PR-AWS-CFR-SNS-006",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure AWS SNS topic policy is not overly permissive for publishing.",
    "Policy Description": "It identifies AWS SNS topics that have SNS policy overly permissive for publishing. When a message is published, Amazon SNS attempts to deliver the message to the subscribed endpoints. To protect these messages from attackers and unauthorized accesses, permissions should be given to only authorized users. For more details: https://docs.aws.amazon.com/sns/latest/dg/sns-security-best-practices.html#implement-least-privilege-access",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-sns-policy.html"
}


#
# PR-AWS-CFR-SNS-007
#

default sns_permissive_for_subscription = null

action_for_subscription := ["sns:subscribe", "sns:receive"]

aws_issue["sns_permissive_for_subscription"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::sns::topicpolicy"
    policy := json.unmarshal(resource.Properties.PolicyDocument)
    statement:= policy.Statement[_]
    lower(statement.Effect) == "allow"
    statement.Principal == "*"
    contains(lower(statement.Action[i]), action_for_subscription[j])
    not statement.Condition
}

aws_issue["sns_permissive_for_subscription"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::sns::topicpolicy"
    policy := json.unmarshal(resource.Properties.PolicyDocument)
    statement:= policy.Statement[_]
    lower(statement.Effect) == "allow"
    statement.Principal.AWS == "*"
    contains(lower(statement.Action[i]), action_for_subscription[j])
    not statement.Condition
}

aws_issue["sns_permissive_for_subscription"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::sns::topicpolicy"
    policy := json.unmarshal(resource.Properties.PolicyDocument)
    statement:= policy.Statement[_]
    lower(statement.Effect) == "allow"
    statement.Principal.AWS[_] = "*"
    contains(lower(statement.Action[i]), action_for_subscription[j])
    not statement.Condition
}


sns_permissive_for_subscription {
    lower(input.Resources[i].Type) == "aws::sns::topicpolicy"
    not aws_issue["sns_permissive_for_subscription"]
}

sns_permissive_for_subscription = false {
    aws_issue["sns_permissive_for_subscription"]
}

sns_permissive_for_subscription_err = "Ensure AWS SNS topic policy is not overly permissive for subscription." {
    aws_issue["sns_permissive_for_subscription"]
}

sns_permissive_for_subscription_metadata := {
    "Policy Code": "PR-AWS-CFR-SNS-007",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure AWS SNS topic policy is not overly permissive for subscription.",
    "Policy Description": "It identifies AWS SNS topics that have SNS policy overly permissive for the subscription. When you subscribe an endpoint to a topic, the endpoint begins to receive messages published to the associated topic. To protect these messages from attackers and unauthorized accesses, permissions should be given to only authorized users. For more details: https://docs.aws.amazon.com/sns/latest/dg/sns-security-best-practices.html#implement-least-privilege-access",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-sns-policy.html"
}

#
# PR-AWS-CFR-SNS-008
#

default sns_cross_account_access = null

aws_issue["sns_cross_account_access"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::sns::topicpolicy"
    policy := json.unmarshal(resource.Properties.PolicyDocument)
    statement:= policy.Statement[_]
    lower(statement.Effect) == "allow"
    statement.Principal != "*"
}

aws_issue["sns_cross_account_access"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::sns::topicpolicy"
    policy := json.unmarshal(resource.Properties.PolicyDocument)
    statement:= policy.Statement[_]
    lower(statement.Effect) == "allow"
    statement.Principal.AWS != "*"
}

aws_issue["sns_cross_account_access"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::sns::topicpolicy"
    policy := json.unmarshal(resource.Properties.PolicyDocument)
    statement:= policy.Statement[_]
    lower(statement.Effect) == "allow"
    statement.Principal.AWS[_] != "*"
}

aws_issue["sns_cross_account_access"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::sns::topicpolicy"
    policy := json.unmarshal(resource.Properties.PolicyDocument)
    statement:= policy.Statement[_]
    lower(statement.Effect) == "allow"
    contains(statement.Principal.AWS, "arn")
}

aws_issue["sns_cross_account_access"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::sns::topicpolicy"
    policy := json.unmarshal(resource.Properties.PolicyDocument)
    statement:= policy.Statement[_]
    lower(statement.Effect) == "allow"
    contains(statement.Principal.AWS[_], "arn")
}

aws_issue["sns_cross_account_access"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::sns::topicpolicy"
    policy := json.unmarshal(resource.Properties.PolicyDocument)
    statement:= policy.Statement[_]
    lower(statement.Effect) == "allow"
    not contains(statement.Principal.AWS, "$.Owner")
}

aws_issue["sns_cross_account_access"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::sns::topicpolicy"
    policy := json.unmarshal(resource.Properties.PolicyDocument)
    statement:= policy.Statement[_]
    lower(statement.Effect) == "allow"
    not contains(statement.Principal.AWS[_], "$.Owner")
}

sns_cross_account_access {
    lower(input.Resources[i].Type) == "aws::sns::topicpolicy"
    not aws_issue["sns_cross_account_access"]
}

sns_cross_account_access = false {
    aws_issue["sns_cross_account_access"]
}

sns_cross_account_access_err = "Ensure AWS SNS topic do not have cross-account access." {
    aws_issue["sns_cross_account_access"]
}

sns_cross_account_access_metadata := {
    "Policy Code": "PR-AWS-CFR-SNS-008",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure AWS SNS topic do not have cross-account access.",
    "Policy Description": "It identifies AWS SNS topics that are configured with cross-account access. Allowing unknown cross-account access to your SNS topics will enable other accounts and gain control over your AWS SNS topics. To prevent unknown cross-account access, allow only trusted entities to access your Amazon SNS topics by implementing the appropriate SNS policies.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-sns-policy.html"
}


#
# PR-AWS-CFR-SNS-009
#

default sns_accessible_via_specific_vpc = null

aws_issue["sns_accessible_via_specific_vpc"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::sns::topicpolicy"
    policy := json.unmarshal(resource.Properties.PolicyDocument)
    statement:= policy.Statement[_]
    not contains(lower(statement.Condition.StringEquals), "aws:sourcevpce")
}

sns_accessible_via_specific_vpc {
    lower(input.Resources[i].Type) == "aws::sns::topicpolicy"
    not aws_issue["sns_accessible_via_specific_vpc"]
}

sns_accessible_via_specific_vpc = false {
    aws_issue["sns_accessible_via_specific_vpc"]
}

sns_accessible_via_specific_vpc_err = "Ensure SNS is only accessible via specific VPCe service." {
    aws_issue["sns_accessible_via_specific_vpc"]
}

sns_accessible_via_specific_vpc_metadata := {
    "Policy Code": "PR-AWS-CFR-SNS-009",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure SNS is only accessible via specific VPCe service.",
    "Policy Description": "It checks if SNS to other AWS services communication is over the internet.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-sns-policy.html"
}


#
# PR-AWS-CFR-SNS-010
#

default sns_secure_data_transport = null

aws_issue["sns_secure_data_transport"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::sns::topicpolicy"
    policy := json.unmarshal(resource.Properties.PolicyDocument)
    statement:= policy.Statement[_]
    not statement.Condition.Bool["aws:SecureTransport"]
}

aws_issue["sns_secure_data_transport"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::sns::topicpolicy"
    policy := json.unmarshal(resource.Properties.PolicyDocument)
    statement:= policy.Statement[_]
    lower(statement.Effect) == "allow"
    statement.Principal.AWS == "*"
    contains(lower(statement.Action[_]), "publish")
    lower(statement.Condition.Bool["aws:SecureTransport"]) == "false"
}

aws_issue["sns_secure_data_transport"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::sns::topicpolicy"
    policy := json.unmarshal(resource.Properties.PolicyDocument)
    statement:= policy.Statement[_]
    lower(statement.Effect) == "allow"
    statement.Principal.AWS[_] = "*"
    contains(lower(statement.Action[_]), "publish")
    lower(statement.Condition.Bool["aws:SecureTransport"]) == "false"
}

aws_issue["sns_secure_data_transport"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::sns::topicpolicy"
    policy := json.unmarshal(resource.Properties.PolicyDocument)
    statement:= policy.Statement[_]
    lower(statement.Effect) == "deny"
    statement.Principal.AWS == "*"
    contains(lower(statement.Action[_]), "publish")
    lower(statement.Condition.Bool["aws:SecureTransport"]) == "true"
}

aws_issue["sns_secure_data_transport"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::sns::topicpolicy"
    policy := json.unmarshal(resource.Properties.PolicyDocument)
    statement:= policy.Statement[_]
    lower(statement.Effect) == "deny"
    statement.Principal.AWS[_] = "*"
    contains(lower(statement.Action[_]), "publish")
    lower(statement.Condition.Bool["aws:SecureTransport"]) == "true"
}

sns_secure_data_transport {
    lower(input.Resources[i].Type) == "aws::sns::topicpolicy"
    not aws_issue["sns_secure_data_transport"]
}

sns_secure_data_transport = false {
    aws_issue["sns_secure_data_transport"]
}

sns_secure_data_transport_err = "Ensure SNS topic is configured with secure data transport policy." {
    aws_issue["sns_secure_data_transport"]
}

sns_secure_data_transport_metadata := {
    "Policy Code": "PR-AWS-CFR-SNS-010",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure SNS topic is configured with secure data transport policy.",
    "Policy Description": "It check if the SNs topics are configured with secure data transport policy via SSL.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-sns-policy.html"
}