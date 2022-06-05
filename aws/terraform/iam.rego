package rule


#
# PR-AWS-TRF-IAM-001
#
default iam_wildcard_resource = null

aws_issue["iam_wildcard_resource"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_policy"
    statement := resource.properties.policy.Statement[j]
    lower(statement.Resource) == "*"
}

source_path[{"iam_wildcard_resource": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_policy"
    statement := resource.properties.policy.Statement[j]
    lower(statement.Resource) == "*"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "policy", "Statement", j, "Resource"]
        ],
    }
}

iam_wildcard_resource {
    lower(input.resources[i].type) == "aws_iam_policy"
    not aws_issue["iam_wildcard_resource"]
}

iam_wildcard_resource = false {
    aws_issue["iam_wildcard_resource"]
}

iam_wildcard_resource_err = "Ensure no wildcards are specified in IAM policy with 'Resource' section" {
    aws_issue["iam_wildcard_resource"]
}

iam_wildcard_resource_metadata := {
    "Policy Code": "PR-AWS-TRF-IAM-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure no wildcards are specified in IAM policy with 'Resource' section",
    "Policy Description": "Using a wildcard in the Resource element in a role's trust policy would allow any IAM user in an account to access all resources. This is a significant security gap and can be used to gain access to sensitive data.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html"
}

#
# PR-AWS-TRF-IAM-002
#
default iam_wildcard_action = null

aws_issue["iam_wildcard_action"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_policy"
    statement := resource.properties.policy.Statement[j]
    lower(statement.Action) == "*"
}

source_path[{"iam_wildcard_action": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_policy"
    statement := resource.properties.policy.Statement[j]
    lower(statement.Action) == "*"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "policy", "Statement", j, "Action"]
        ],
    }
}

iam_wildcard_action {
    lower(input.resources[i].type) == "aws_iam_policy"
    not aws_issue["iam_wildcard_action"]
}

iam_wildcard_action = false {
    aws_issue["iam_wildcard_action"]
}

iam_wildcard_action_err = "Ensure no wildcards are specified in IAM policy with 'Action' section" {
    aws_issue["iam_wildcard_action"]
}

iam_wildcard_action_metadata := {
    "Policy Code": "PR-AWS-TRF-IAM-002",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure no wildcards are specified in IAM policy with 'Action' section",
    "Policy Description": "Using a wildcard in the Action element in a role's trust policy would allow any IAM user in an account to Manage all resources and a user can manipulate data. This is a significant security gap and can be used to gain access to sensitive data.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html"
}

#
# PR-AWS-TRF-IAM-003
#
default iam_wildcard_principal = null

aws_issue["iam_wildcard_principal"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_role"
    statement := resource.properties.assume_role_policy.Statement[j]
    lower(statement.Principal) == "*"
}

aws_issue["iam_wildcard_principal"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_role"
    statement := resource.properties.assume_role_policy.Statement[j]
    lower(statement.Principal.AWS) == "*"
}

source_path[{"iam_wildcard_principal": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_role"
    statement := resource.properties.assume_role_policy.Statement[j]
    lower(statement.Principal) == "*"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "assume_role_policy", "Statement", j, "Principal"]
        ],
    }
}

source_path[{"iam_wildcard_principal": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_role"
    statement := resource.properties.assume_role_policy.Statement[j]
    lower(statement.Principal.AWS) == "*"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "assume_role_policy", "Statement", j, "Principal", "AWS"]
        ],
    }
}


iam_wildcard_principal {
    lower(input.resources[i].type) == "aws_iam_role"
    not aws_issue["iam_wildcard_principal"]
}

iam_wildcard_principal = false {
    aws_issue["iam_wildcard_principal"]
}

iam_wildcard_principal_err = "Ensure no wildcards are specified in IAM trust-relationship policy with 'Principal' section" {
    aws_issue["iam_wildcard_principal"]
}

iam_wildcard_principal_metadata := {
    "Policy Code": "PR-AWS-TRF-IAM-003",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure no wildcards are specified in IAM trust-relationship policy with 'Principal' section",
    "Policy Description": "Using a wildcard in the Principal element in a role's trust policy would allow any IAM user in any account to access the role. This is a significant security gap and can be used to gain access to sensitive data.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-role.html"
}

#
# PR-AWS-TRF-IAM-004
#
default iam_resource_format = null

aws_issue["iam_resource_format"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_role"
    statement := resource.properties.assume_role_policy.Statement[j]
    lower(statement.Resource) == "arn:aws:*:*"
}

source_path[{"iam_resource_format": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_role"
    statement := resource.properties.assume_role_policy.Statement[j]
    lower(statement.Resource) == "arn:aws:*:*"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "assume_role_policy", "Statement", j, "Resource"]
        ],
    }
}

aws_issue["iam_resource_format"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_user_policy"
    statement := resource.properties.policy.Statement[j]
    lower(statement.Resource) == "arn:aws:*:*"
}

source_path[{"iam_resource_format": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_user_policy"
    statement := resource.properties.policy.Statement[j]
    lower(statement.Resource) == "arn:aws:*:*"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "policy", "Statement", "Resource"]
        ],
    }
}

aws_issue["iam_resource_format"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_group_policy"
    statement := resource.properties.policy.Statement[j]
    lower(statement.Resource) == "arn:aws:*:*"
}

source_path[{"iam_resource_format": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_group_policy"
    statement := resource.properties.policy.Statement[j]
    lower(statement.Resource) == "arn:aws:*:*"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "policy", "Statement", j, "Resource"]
        ],
    }
}

iam_resource_format {
    lower(input.resource[i].type) == "aws_iam_role"
    not aws_issue["iam_resource_format"]
}

iam_resource_format {
    lower(input.resource[i].type) == "aws_iam_user_policy"
    not aws_issue["iam_resource_format"]
}

iam_resource_format {
    lower(input.resource[i].type) == "aws_iam_group_policy"
    not aws_issue["iam_resource_format"]
}

iam_resource_format = false {
    aws_issue["iam_resource_format"]
}

iam_resource_format_err = "Ensure no IAM policy has a resource specified in the following format:'arn:aws:*:*'" {
    aws_issue["iam_resource_format"]
}

iam_resource_format_metadata := {
    "Policy Code": "PR-AWS-TRF-IAM-004",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure no IAM policy has a resource specified in the following format:'arn:aws:*:*'",
    "Policy Description": "Ensure no IAM policy has a resource specified in the following format:'arn:aws:*:*' AWS only allows fully qualified ARNs or '*'. The above mentioned ARN is not supported in an identity-based policy",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html"
}

#
# PR-AWS-TRF-IAM-005
#
default iam_assume_permission = null

aws_issue["iam_assume_permission"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_policy"
    statement := resource.properties.policy.Statement[j]
    lower(statement.Effect) == "allow"
    contains(lower(statement.Action), "sts:assumerole")
    statement.Condition == "*"
}

source_path[{"iam_assume_permission": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_policy"
    statement := resource.properties.policy.Statement[j]
    lower(statement.Effect) == "allow"
    contains(lower(statement.Action), "sts:assumerole")
    statement.Condition == "*"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "policy", "Statement", j, "Condition"]
        ],
    }
}

aws_issue["iam_assume_permission"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_policy"
    statement := resource.properties.policy.Statement[j]
    lower(statement.Effect) == "allow"
    contains(lower(statement.Action), "sts:assumerole")
    not statement.Condition
}

source_path[{"iam_assume_permission": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_policy"
    statement := resource.properties.policy.Statement[j]
    lower(statement.Effect) == "allow"
    contains(lower(statement.Action), "sts:assumerole")
    not statement.Condition

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "policy", "Statement", j, "Condition"]
        ],
    }
}

iam_assume_permission {
    lower(input.resources[i].type) == "aws_iam_policy"
    not aws_issue["iam_assume_permission"]
}

iam_assume_permission = false {
    aws_issue["iam_assume_permission"]
}

iam_assume_permission_err = "AWS IAM policy allows assume role permission across all services" {
    aws_issue["iam_assume_permission"]
}

iam_assume_permission_metadata := {
    "Policy Code": "PR-AWS-TRF-IAM-005",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS IAM policy allows assume role permission across all services",
    "Policy Description": "This policy identifies AWS IAM policy which allows assume role permission across all services. Typically, AssumeRole is used if you have multiple accounts and need to access resources from each account then you can create long term credentials in one account and then use temporary security credentials to access all the other accounts by assuming roles in those accounts.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html"
}

#
# PR-AWS-TRF-IAM-006
#
default iam_all_traffic = null

aws_issue["iam_all_traffic"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_policy"
    statement := resource.properties.policy.Statement[j]
    source_ip := statement.Condition["ForAnyValue:IpAddress"]["aws:SourceIp"][_]
    lower(source_ip) == "0.0.0.0/0"
}

source_path[{"iam_all_traffic": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_policy"
    statement := resource.properties.policy.Statement[j]
    source_ip := statement.Condition["ForAnyValue:IpAddress"]["aws:SourceIp"][_]
    lower(source_ip) == "0.0.0.0/0"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "policy", "Statement", j, "Condition", "ForAnyValue:IpAddress", "aws:SourceIp"]
        ],
    }
}

iam_all_traffic {
    lower(input.resources[i].type) == "aws_iam_policy"
    not aws_issue["iam_all_traffic"]
}

iam_all_traffic = false {
    aws_issue["iam_all_traffic"]
}

iam_all_traffic_err = "AWS IAM policy is overly permissive to all traffic via condition clause" {
    aws_issue["iam_all_traffic"]
}

iam_all_traffic_metadata := {
    "Policy Code": "PR-AWS-TRF-IAM-006",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS IAM policy is overly permissive to all traffic via condition clause",
    "Policy Description": "This policy identifies IAM policies that have a policy that is overly permissive to all traffic via condition clause. If any IAM policy statement with a condition containing 0.0.0.0/0 or ::/0, it allows all traffic to resources attached to that IAM policy. It is highly recommended to have the least privileged IAM policy to protect the data leakage and unauthorized access.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html"
}

#
# PR-AWS-TRF-IAM-007
#
default iam_administrative_privileges = null

aws_issue["iam_administrative_privileges"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_policy"
    statement := resource.properties.policy.Statement[j]
    statement.Action == "*"
    statement.Resource == "*"
    lower(statement.Effect) == "allow"
}

source_path[{"iam_administrative_privileges": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_policy"
    statement := resource.properties.policy.Statement[j]
    statement.Action == "*"
    statement.Resource == "*"
    lower(statement.Effect) == "allow"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "policy", "Statement", j, "Action"],
            ["resources", i, "properties", "policy", "Statement", j, "Resource"]
        ],
    }
}

iam_administrative_privileges {
    lower(input.resources[i].type) == "aws_iam_policy"
    not aws_issue["iam_administrative_privileges"]
}

iam_administrative_privileges = false {
    aws_issue["iam_administrative_privileges"]
}

iam_administrative_privileges_err = "AWS IAM policy allows full administrative privileges" {
    aws_issue["iam_administrative_privileges"]
}

iam_administrative_privileges_metadata := {
    "Policy Code": "PR-AWS-TRF-IAM-007",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS IAM policy allows full administrative privileges",
    "Policy Description": "This policy identifies IAM policies with full administrative privileges. IAM policies are the means by which privileges are granted to users, groups, or roles. It is recommended and considered a standard security advice to grant least privilege like granting only the permissions required to perform a task. Determine what users need to do and then craft policies for them that let the users perform only those tasks, instead of allowing full administrative privileges.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html"
}

#
# PR-AWS-TRF-IAM-008
#
default iam_user_group_attach = null

aws_issue["iam_user_group_attach"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_group_membership"
    not resource.properties.users
}

source_path[{"iam_user_group_attach": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_group_membership"
    not resource.properties.users
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "users"]
        ],
    }
}

aws_issue["iam_user_group_attach"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_group_membership"
    count(resource.properties.users) < 1
}

source_path[{"iam_user_group_attach": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_group_membership"
    count(resource.properties.users) < 1
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "users"]
        ],
    }
}

iam_user_group_attach {
    lower(input.resources[i].type) == "aws_iam_group_membership"
    not aws_issue["iam_user_group_attach"]
}

iam_user_group_attach = false {
    aws_issue["iam_user_group_attach"]
}

iam_user_group_attach_err = "Ensure IAM groups contains at least one IAM user" {
    aws_issue["iam_user_group_attach"]
}

iam_user_group_attach_metadata := {
    "Policy Code": "PR-AWS-TRF-IAM-008",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure IAM groups contains at least one IAM user",
    "Policy Description": "Ensure that your Amazon Identity and Access Management (IAM) users are members of at least one IAM group in order to adhere to IAM security best practices",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_group_membership"
}
