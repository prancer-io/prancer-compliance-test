package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sns-subscription.html
# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-sns-topic.html

has_property(parent_object, target_property) { 
	_ = parent_object[target_property]
}

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


#
# PR-AWS-CLD-SNS-005
# aws::sns::topicpolicy

default sns_not_unauthorized_access = true

sns_not_unauthorized_access = false {
    policy := json.unmarshal(input.Attributes.Policy)
    statement := policy.Statement[_]
    lower(statement.Effect) == "allow"
    statement.Principal == "*"
    not statement.Condition
}

sns_not_unauthorized_access = false {
    policy := json.unmarshal(input.Attributes.Policy)
    statement := policy.Statement[_]
    lower(statement.Effect) == "allow"
    statement.Principal.AWS == "*"
    not statement.Condition
}

sns_not_unauthorized_access = false {
    policy := json.unmarshal(input.Attributes.Policy)
    statement := policy.Statement[_]
    lower(statement.Effect) == "allow"
    statement.Principal.AWS[_] = "*"
    not statement.Condition
}

sns_not_unauthorized_access_err = "Ensure AWS SNS topic is not exposed to unauthorized access." {
    not sns_not_unauthorized_access
}

sns_not_unauthorized_access_metadata := {
    "Policy Code": "PR-AWS-CLD-SNS-005",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS SNS topic is not exposed to unauthorized access.",
    "Policy Description": "It identifies AWS SNS topics that are exposed to unauthorized access. Amazon Simple Notification Service (Amazon SNS) is a web service that coordinates and manages the delivery or sending of messages to subscribing endpoints or clients. To protect these messages from attackers and unauthorized accesses, permissions should be given to only authorized users. For more details: https://docs.aws.amazon.com/sns/latest/dg/sns-security-best-practices.html#ensure-topics-not-publicly-accessible",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sns.html#SNS.Client.get_topic_attributes"
}


#
# PR-AWS-CLD-SNS-006
# aws::sns::topicpolicy

default sns_permissive_for_publishing = true

sns_permissive_for_publishing = false {
    policy := json.unmarshal(input.Attributes.Policy)
    statement := policy.Statement[_]
    lower(statement.Effect) == "allow"
    statement.Principal == "*"
    contains(lower(statement.Action[_]), "sns:publish")
    not statement.Condition
}

sns_permissive_for_publishing = false {
    policy := json.unmarshal(input.Attributes.Policy)
    statement := policy.Statement[_]
    lower(statement.Effect) == "allow"
    statement.Principal == "*"
    contains(lower(statement.Action), "sns:publish")
    not statement.Condition
}

sns_permissive_for_publishing = false {
    policy := json.unmarshal(input.Attributes.Policy)
    statement := policy.Statement[_]
    lower(statement.Effect) == "allow"
    statement.Principal.AWS == "*"
    contains(lower(statement.Action[_]), "sns:publish")
    not statement.Condition
}

sns_permissive_for_publishing = false {
    policy := json.unmarshal(input.Attributes.Policy)
    statement := policy.Statement[_]
    lower(statement.Effect) == "allow"
    statement.Principal.AWS == "*"
    contains(lower(statement.Action), "sns:publish")
    not statement.Condition
}

sns_permissive_for_publishing = false {
    policy := json.unmarshal(input.Attributes.Policy)
    statement := policy.Statement[_]
    lower(statement.Effect) == "allow"
    statement.Principal.AWS[_] = "*"
    contains(lower(statement.Action[_]), "sns:publish")
    not statement.Condition
}

sns_permissive_for_publishing = false {
    policy := json.unmarshal(input.Attributes.Policy)
    statement := policy.Statement[_]
    lower(statement.Effect) == "allow"
    statement.Principal.AWS[_] = "*"
    contains(lower(statement), "sns:publish")
    not statement.Condition
}

sns_permissive_for_publishing_err = "Ensure AWS SNS topic policy is not overly permissive for publishing." {
    not sns_permissive_for_publishing
}

sns_permissive_for_publishing_metadata := {
    "Policy Code": "PR-AWS-CLD-SNS-006",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS SNS topic policy is not overly permissive for publishing.",
    "Policy Description": "It identifies AWS SNS topics that have SNS policy overly permissive for publishing. When a message is published, Amazon SNS attempts to deliver the message to the subscribed endpoints. To protect these messages from attackers and unauthorized accesses, permissions should be given to only authorized users. For more details: https://docs.aws.amazon.com/sns/latest/dg/sns-security-best-practices.html#implement-least-privilege-access",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sns.html#SNS.Client.get_topic_attributes"
}


#
# PR-AWS-CLD-SNS-007
# aws::sns::topicpolicy

default sns_permissive_for_subscription = true

action_for_subscription := ["sns:subscribe", "sns:receive"]

sns_permissive_for_subscription = false {
    policy := json.unmarshal(input.Attributes.Policy)
    statement := policy.Statement[_]
    lower(statement.Effect) == "allow"
    statement.Principal == "*"
    contains(lower(statement.Action[i]), action_for_subscription[j])
    not statement.Condition
}

sns_permissive_for_subscription = false {
    policy := json.unmarshal(input.Attributes.Policy)
    statement := policy.Statement[_]
    lower(statement.Effect) == "allow"
    statement.Principal == "*"
    contains(lower(statement.Action), action_for_subscription[j])
    not statement.Condition
}

sns_permissive_for_subscription = false {
    policy := json.unmarshal(input.Attributes.Policy)
    statement := policy.Statement[_]
    lower(statement.Effect) == "allow"
    statement.Principal.AWS == "*"
    contains(lower(statement.Action[i]), action_for_subscription[j])
    not statement.Condition
}

sns_permissive_for_subscription = false {
    policy := json.unmarshal(input.Attributes.Policy)
    statement := policy.Statement[_]
    lower(statement.Effect) == "allow"
    statement.Principal.AWS == "*"
    contains(lower(statement.Action), action_for_subscription[j])
    not statement.Condition
}

sns_permissive_for_subscription = false {
    policy := json.unmarshal(input.Attributes.Policy)
    statement := policy.Statement[_]
    lower(statement.Effect) == "allow"
    statement.Principal.AWS[_] = "*"
    contains(lower(statement.Action[i]), action_for_subscription[j])
    not statement.Condition
}

sns_permissive_for_subscription = false {
    policy := json.unmarshal(input.Attributes.Policy)
    statement := policy.Statement[_]
    lower(statement.Effect) == "allow"
    statement.Principal.AWS[_] = "*"
    contains(lower(statement.Action), action_for_subscription[j])
    not statement.Condition
}

sns_permissive_for_subscription_err = "Ensure AWS SNS topic policy is not overly permissive for subscription." {
    not sns_permissive_for_subscription
}

sns_permissive_for_subscription_metadata := {
    "Policy Code": "PR-AWS-CLD-SNS-007",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS SNS topic policy is not overly permissive for subscription.",
    "Policy Description": "It identifies AWS SNS topics that have SNS policy overly permissive for the subscription. When you subscribe an endpoint to a topic, the endpoint begins to receive messages published to the associated topic. To protect these messages from attackers and unauthorized accesses, permissions should be given to only authorized users. For more details: https://docs.aws.amazon.com/sns/latest/dg/sns-security-best-practices.html#implement-least-privilege-access",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sns.html#SNS.Client.get_topic_attributes"
}


#
# PR-AWS-CLD-SNS-008
# aws::sns::topicpolicy

default sns_cross_account_access = true

sns_cross_account_access = false {
    policy := json.unmarshal(input.Attributes.Policy)
    statement := policy.Statement[_]
    lower(statement.Effect) == "allow"
    statement.Principal != "*"
    statement.Principal.AWS != "*"
    contains(statement.Principal.AWS, "arn")
    not contains(statement.Principal.AWS, "$.Owner")
}

sns_cross_account_access = false {
    policy := json.unmarshal(input.Attributes.Policy)
    statement := policy.Statement[_]
    lower(statement.Effect) == "allow"
    statement.Principal != "*"
    principal_aws := statement.Principal.AWS[_] 
    principal_aws != "*"
    contains(principal_aws, "arn")
    not contains(principal_aws, "$.Owner")
}

sns_cross_account_access = false {
    policy := json.unmarshal(input.Attributes.Policy)
    statement := policy.Statement[_]
    lower(statement.Effect) == "allow"
    not contains(statement.Principal.AWS[_], "$.Owner")
}

sns_cross_account_access_err = "Ensure AWS SNS topic do not have cross-account access." {
    not sns_cross_account_access
}

sns_cross_account_access_metadata := {
    "Policy Code": "PR-AWS-CLD-SNS-008",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS SNS topic do not have cross-account access.",
    "Policy Description": "It identifies AWS SNS topics that are configured with cross-account access. Allowing unknown cross-account access to your SNS topics will enable other accounts and gain control over your AWS SNS topics. To prevent unknown cross-account access, allow only trusted entities to access your Amazon SNS topics by implementing the appropriate SNS policies.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sns.html#SNS.Client.get_topic_attributes"
}


#
# PR-AWS-CLD-SNS-009
# aws::sns::topicpolicy

default sns_accessible_via_specific_vpc = true

sns_accessible_via_specific_vpc = false {
    policy := json.unmarshal(input.Attributes.Policy)
    statement := policy.Statement[_]
    lower(statement.Effect) == "allow"
    not has_property(statement, "Condition")
}

sns_accessible_via_specific_vpc = false {
    policy := json.unmarshal(input.Attributes.Policy)
    statement := policy.Statement[_]
    lower(statement.Effect) == "allow"
    not has_property(statement.Condition, "StringEquals")
}

sns_accessible_via_specific_vpc = false {
    policy := json.unmarshal(input.Attributes.Policy)
    statement := policy.Statement[_]
    lower(statement.Effect) == "allow"
    not has_property(statement.Condition.StringEquals, "aws:SourceVpce")
}

sns_accessible_via_specific_vpc_err = "Ensure SNS is only accessible via specific VPCe service." {
    not sns_accessible_via_specific_vpc
}

sns_accessible_via_specific_vpc_metadata := {
    "Policy Code": "PR-AWS-CLD-SNS-009",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure SNS is only accessible via specific VPCe service.",
    "Policy Description": "It checks if SNS to other AWS services communication is over the internet.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sns.html#SNS.Client.get_topic_attributes"
}


#
# PR-AWS-CLD-SNS-010
# aws::sns::topicpolicy

default sns_secure_data_transport = true

sns_secure_data_transport = false {
    policy := json.unmarshal(input.Attributes.Policy)
    statement := policy.Statement[_]
    not statement.Condition.Bool["aws:SecureTransport"]
}

sns_secure_data_transport = false {
    policy := json.unmarshal(input.Attributes.Policy)
    statement := policy.Statement[_]
    lower(statement.Effect) == "allow"
    statement.Principal.AWS == "*"
    contains(lower(statement.Action[_]), "publish")
    lower(statement.Condition.Bool["aws:SecureTransport"]) == "false"
}

sns_secure_data_transport = false {
    policy := json.unmarshal(input.Attributes.Policy)
    statement := policy.Statement[_]
    lower(statement.Effect) == "allow"
    statement.Principal.AWS == "*"
    contains(lower(statement.Action), "publish")
    lower(statement.Condition.Bool["aws:SecureTransport"]) == "false"
}


sns_secure_data_transport = false {
    policy := json.unmarshal(input.Attributes.Policy)
    statement := policy.Statement[_]
    lower(statement.Effect) == "allow"
    statement.Principal.AWS[_] = "*"
    contains(lower(statement.Action[_]), "publish")
    lower(statement.Condition.Bool["aws:SecureTransport"]) == "false"
}

sns_secure_data_transport = false {
    policy := json.unmarshal(input.Attributes.Policy)
    statement := policy.Statement[_]
    lower(statement.Effect) == "allow"
    statement.Principal.AWS[_] = "*"
    contains(lower(statement.Action), "publish")
    lower(statement.Condition.Bool["aws:SecureTransport"]) == "false"
}

sns_secure_data_transport = false {
    policy := json.unmarshal(input.Attributes.Policy)
    statement := policy.Statement[_]
    lower(statement.Effect) == "deny"
    statement.Principal.AWS == "*"
    contains(lower(statement.Action[_]), "publish")
    lower(statement.Condition.Bool["aws:SecureTransport"]) == "true"
}

sns_secure_data_transport = false {
    policy := json.unmarshal(input.Attributes.Policy)
    statement := policy.Statement[_]
    lower(statement.Effect) == "deny"
    statement.Principal.AWS == "*"
    contains(lower(statement.Action), "publish")
    lower(statement.Condition.Bool["aws:SecureTransport"]) == "true"
}

sns_secure_data_transport = false {
    policy := json.unmarshal(input.Attributes.Policy)
    statement := policy.Statement[_]
    lower(statement.Effect) == "deny"
    statement.Principal.AWS[_] = "*"
    contains(lower(statement.Action[_]), "publish")
    lower(statement.Condition.Bool["aws:SecureTransport"]) == "true"
}

sns_secure_data_transport = false {
    policy := json.unmarshal(input.Attributes.Policy)
    statement := policy.Statement[_]
    lower(statement.Effect) == "deny"
    statement.Principal.AWS[_] = "*"
    contains(lower(statement.Action), "publish")
    lower(statement.Condition.Bool["aws:SecureTransport"]) == "true"
}

sns_secure_data_transport_err = "Ensure SNS topic is configured with secure data transport policy." {
    not sns_secure_data_transport
}

sns_secure_data_transport_metadata := {
    "Policy Code": "PR-AWS-CLD-SNS-010",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure SNS topic is configured with secure data transport policy.",
    "Policy Description": "It check if the SNs topics are configured with secure data transport policy via SSL.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sns.html#SNS.Client.get_topic_attributes"
}
