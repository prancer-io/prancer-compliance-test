package rule

has_property(parent_object, target_property) { 
	_ = parent_object[target_property]
}

iam_policies_condition := ["aws:SourceArn", "aws:VpcSourceIp", "aws:username", "aws:userid", "aws:SourceVpc", "aws:SourceIp", "aws:SourceIdentity", "aws:SourceAccount", "aws:PrincipalOrgID", "aws:PrincipalArn", "AWS:SourceOwner", "kms:CallerAccount"]

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

#
# PR-AWS-TRF-IAM-011
#

default iam_policy_not_overly_permissive_to_all_traffic = null

ip_address = ["0.0.0.0/0", "::/0"]

aws_issue["iam_policy_not_overly_permissive_to_all_traffic"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_policy"
    statement := resource.properties.policy.Statement[j]
    lower(statement.Effect) == "allow"
    statement.Condition.IpAddress["aws:SourceIp"] == ip_address[_]
    contains(lower(statement.Action), "lambda:")
}

aws_issue["iam_policy_not_overly_permissive_to_all_traffic"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_policy"
    statement := resource.properties.policy.Statement[j]
    lower(statement.Effect) == "allow"
    statement.Condition.IpAddress["aws:SourceIp"] == ip_address[_]
    contains(lower(statement.Action[_]), "lambda:")
}

aws_issue["iam_policy_not_overly_permissive_to_all_traffic"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_policy"
    statement := resource.properties.policy.Statement[j]
    lower(statement.Effect) == "allow"
    statement.Condition.IpAddress["ForAnyValue:IpAddress"]["aws:SourceIp"] == ip_address[_]
    contains(lower(statement.Action[_]), "lambda:")
}

aws_issue["iam_policy_not_overly_permissive_to_all_traffic"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_policy"
    statement := resource.properties.policy.Statement[j]
    lower(statement.Effect) == "allow"
    statement.Condition.IpAddress["ForAnyValue:IpAddress"]["aws:SourceIp"] == ip_address[_]
    contains(lower(statement.Action), "lambda:")
}

iam_policy_not_overly_permissive_to_all_traffic {
    lower(input.resources[i].type) == "aws_iam_policy"
    not aws_issue["iam_policy_not_overly_permissive_to_all_traffic"]
}

iam_policy_not_overly_permissive_to_all_traffic = false {
    aws_issue["iam_policy_not_overly_permissive_to_all_traffic"]
}

iam_policy_not_overly_permissive_to_all_traffic_err = "Ensure Lambda IAM policy is not overly permissive to all traffic" {
    aws_issue["iam_policy_not_overly_permissive_to_all_traffic"]
}

iam_policy_not_overly_permissive_to_all_traffic_metadata := {
    "Policy Code": "PR-AWS-TRF-IAM-011",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure Lambda IAM policy is not overly permissive to all traffic",
    "Policy Description": "Ensure that the Lambda should be granted access restrictions so that only authorized users and applications have access to the service. For more details: https://docs.aws.amazon.com/lambda/latest/dg/security-iam.html",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy"
}

#
# PR-AWS-TRF-IAM-012
#

default iam_policy_not_overly_permissive_to_lambda_service = null

aws_issue["iam_policy_not_overly_permissive_to_lambda_service"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_policy"
    statement := resource.properties.policy.Statement[j]
    lower(statement.Action[_]) == "lambda:*"
    statement.Resource[_] == "*"
    not statement.Condition
}

aws_issue["iam_policy_not_overly_permissive_to_lambda_service"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_policy"
    statement := resource.properties.policy.Statement[j]
    lower(statement.Action) == "lambda:*"
    statement.Resource[_] == "*"
    not statement.Condition
}
aws_issue["iam_policy_not_overly_permissive_to_lambda_service"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_policy"
    statement := resource.properties.policy.Statement[j]
    lower(statement.Action[_]) == "lambda:*"
    statement.Resource == "*"
    not statement.Condition
}

aws_issue["iam_policy_not_overly_permissive_to_lambda_service"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_policy"
    statement := resource.properties.policy.Statement[j]
    lower(statement.Action) == "lambda:*"
    statement.Resource == "*"
    not statement.Condition
}

iam_policy_not_overly_permissive_to_lambda_service {
    lower(input.resources[i].type) == "aws_iam_policy"
    not aws_issue["iam_policy_not_overly_permissive_to_lambda_service"]
}

iam_policy_not_overly_permissive_to_lambda_service = false {
    aws_issue["iam_policy_not_overly_permissive_to_lambda_service"]
}

iam_policy_not_overly_permissive_to_lambda_service_err = "Ensure IAM policy is not overly permissive to Lambda service" {
    aws_issue["iam_policy_not_overly_permissive_to_lambda_service"]
}

iam_policy_not_overly_permissive_to_lambda_service_metadata := {
    "Policy Code": "PR-AWS-TRF-IAM-012",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure IAM policy is not overly permissive to Lambda service",
    "Policy Description": "Ensure the principle of least privileges by ensuring that only restricted Lambda services for restricted resources.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy"
}

#
# PR-AWS-TRF-IAM-013
#

default ec2_instance_with_iam_permissions_management_access = null

action := ["iam:AttachGroupPolicy","iam:AttachRolePolicy","iam:AttachUserPolicy","iam:CreatePolicy","iam:CreatePolicyVersion","iam:DeleteAccountPasswordPolicy","iam:DeleteGroupPolicy","iam:DeletePolicy","iam:DeletePolicyVersion","iam:DeleteRolePermissionsBoundary","iam:DeleteRolePolicy","iam:DeleteUserPermissionsBoundary","iam:DeleteUserPolicy","iam:DetachGroupPolicy","iam:DetachRolePolicy","iam:DetachUserPolicy","iam:PutGroupPolicy","iam:PutRolePermissionsBoundary","iam:PutRolePolicy","iam:PutUserPermissionsBoundary","iam:PutUserPolicy","iam:SetDefaultPolicyVersion","iam:UpdateAssumeRolePolicy"]

aws_issue["ec2_instance_with_iam_permissions_management_access"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_role"
    statement := resource.properties.assume_role_policy.Statement[j]
    statement.Action[_] == action[_]
    services := statement.Principal.Service[_]
    contains(services, "ec2")
}

aws_issue["ec2_instance_with_iam_permissions_management_access"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_role"
    statement := resource.properties.assume_role_policy.Statement[j]
    statement.Action == action[_]
    services := statement.Principal.Service[_]
    contains(services, "ec2")
}

aws_issue["ec2_instance_with_iam_permissions_management_access"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_role"
    statement := resource.properties.assume_role_policy.Statement[j]
    statement.Action == action[_]
    contains(statement.Principal.Service, "ec2")
}

aws_issue["ec2_instance_with_iam_permissions_management_access"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_role"
    statement := resource.properties.assume_role_policy.Statement[j]
    statement.Action[_] == action[_]
    contains(statement.Principal.Service, "ec2")
}

ec2_instance_with_iam_permissions_management_access {
    lower(input.resources[i].type) == "aws_iam_role"
    not aws_issue["ec2_instance_with_iam_permissions_management_access"]
}

ec2_instance_with_iam_permissions_management_access = false {
    aws_issue["ec2_instance_with_iam_permissions_management_access"]
}

ec2_instance_with_iam_permissions_management_access_err = "Ensure that the AWS EC2 instances don't have a risky set of permissions management access to minimize security risks." {
    aws_issue["ec2_instance_with_iam_permissions_management_access"]
}

ec2_instance_with_iam_permissions_management_access_metadata := {
    "Policy Code": "PR-AWS-TRF-IAM-013",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that the AWS EC2 instances don't have a risky set of permissions management access to minimize security risks.",
    "Policy Description": "This policy identifies IAM permissions management access that is defined as risky permissions. Ensure that the AWS EC2 instances don't have a risky set of permissions management access to minimize security risks.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role"
}

#
# PR-AWS-TRF-IAM-014
#

default lambda_function_with_iam_write_access = null

action_lambda_function_with_iam_write_access := ["iam:AddClientIDToOpenIDConnectProvider","iam:AddRoleToInstanceProfile","iam:AddUserToGroup","iam:ChangePassword","iam:CreateAccessKey","iam:CreateAccountAlias","iam:CreateGroup","iam:CreateInstanceProfile","iam:CreateLoginProfile","iam:CreateOpenIDConnectProvider","iam:CreateRole","iam:CreateSAMLProvider","iam:CreateServiceLinkedRole","iam:CreateServiceSpecificCredential","iam:CreateUser","iam:CreateVirtualMFADevice","iam:DeactivateMFADevice","iam:DeleteAccessKey","iam:DeleteAccountAlias","iam:DeleteGroup","iam:DeleteInstanceProfile","iam:DeleteLoginProfile","iam:DeleteOpenIDConnectProvider","iam:DeleteRole","iam:DeleteSAMLProvider","iam:DeleteSSHPublicKey","iam:DeleteServerCertificate","iam:DeleteServiceLinkedRole","iam:DeleteServiceSpecificCredential","iam:DeleteSigningCertificate","iam:DeleteUser","iam:DeleteVirtualMFADevice","iam:EnableMFADevice","iam:PassRole","iam:RemoveClientIDFromOpenIDConnectProvider","iam:RemoveRoleFromInstanceProfile","iam:RemoveUserFromGroup","iam:ResetServiceSpecificCredential","iam:ResyncMFADevice","iam:SetSecurityTokenServicePreferences","iam:UpdateAccessKey","iam:UpdateAccountPasswordPolicy","iam:UpdateGroup","iam:UpdateLoginProfile","iam:UpdateOpenIDConnectProviderThumbprint","iam:UpdateRole","iam:UpdateRoleDescription","iam:UpdateSAMLProvider","iam:UpdateSSHPublicKey","iam:UpdateServerCertificate","iam:UpdateServiceSpecificCredential","iam:UpdateSigningCertificate","iam:UpdateUser","iam:UploadSSHPublicKey","iam:UploadServerCertificate","iam:UploadSigningCertificate"]

aws_issue["lambda_function_with_iam_write_access"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_role"
    statement := resource.properties.assume_role_policy.Statement[j]
    statement.Action[_] == action_lambda_function_with_iam_write_access[_]
    services := statement.Principal.Service[_]
    contains(services, "lambda")
}

aws_issue["lambda_function_with_iam_write_access"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_role"
    statement := resource.properties.assume_role_policy.Statement[j]
    statement.Action == action_lambda_function_with_iam_write_access[_]
    services := statement.Principal.Service[_]
    contains(services, "lambda")
}

aws_issue["lambda_function_with_iam_write_access"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_role"
    statement := resource.properties.assume_role_policy.Statement[j]
    statement.Action == action_lambda_function_with_iam_write_access[_]
    contains(statement.Principal.Service, "lambda")
}

aws_issue["lambda_function_with_iam_write_access"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_role"
    statement := resource.properties.assume_role_policy.Statement[j]
    statement.Action[_] == action_lambda_function_with_iam_write_access[_]
    contains(statement.Principal.Service, "lambda")
}

lambda_function_with_iam_write_access {
    lower(input.resources[i].type) == "aws_iam_role"
    not aws_issue["lambda_function_with_iam_write_access"]
}

lambda_function_with_iam_write_access = false {
    aws_issue["lambda_function_with_iam_write_access"]
}

lambda_function_with_iam_write_access_err = "Ensure that the AWS Lambda Function instances provisioned in your AWS account don't have a risky set of write permissions to minimize security risks." {
    aws_issue["lambda_function_with_iam_write_access"]
}

lambda_function_with_iam_write_access_metadata := {
    "Policy Code": "PR-AWS-TRF-IAM-014",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that the AWS Lambda Function instances provisioned in your AWS account don't have a risky set of write permissions to minimize security risks.",
    "Policy Description": "This policy identifies IAM write permissions that are defined as risky permissions. Ensure that the AWS Lambda Function instances provisioned in your AWS account don't have a risky set of write permissions to minimize security risks.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role"
}

#
# PR-AWS-TRF-IAM-015
#

default lambda_function_with_iam_permissions_management_access = null

action_lambda_function_with_iam_permissions_management_access := ["iam:AttachGroupPolicy","iam:AttachRolePolicy","iam:AttachUserPolicy","iam:CreatePolicy","iam:CreatePolicyVersion","iam:DeleteAccountPasswordPolicy","iam:DeleteGroupPolicy","iam:DeletePolicy","iam:DeletePolicyVersion","iam:DeleteRolePermissionsBoundary","iam:DeleteRolePolicy","iam:DeleteUserPermissionsBoundary","iam:DeleteUserPolicy","iam:DetachGroupPolicy","iam:DetachRolePolicy","iam:DetachUserPolicy","iam:PutGroupPolicy","iam:PutRolePermissionsBoundary","iam:PutRolePolicy","iam:PutUserPermissionsBoundary","iam:PutUserPolicy","iam:SetDefaultPolicyVersion","iam:UpdateAssumeRolePolicy"]

aws_issue["lambda_function_with_iam_permissions_management_access"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_role"
    statement := resource.properties.assume_role_policy.Statement[j]
    statement.Action[_] == action_lambda_function_with_iam_permissions_management_access[_]
    services := statement.Principal.Service[_]
    contains(services, "lambda")
}

aws_issue["lambda_function_with_iam_permissions_management_access"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_role"
    statement := resource.properties.assume_role_policy.Statement[j]
    statement.Action == action_lambda_function_with_iam_permissions_management_access[_]
    services := statement.Principal.Service[_]
    contains(services, "lambda")
}

aws_issue["lambda_function_with_iam_permissions_management_access"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_role"
    statement := resource.properties.assume_role_policy.Statement[j]
    statement.Action == action_lambda_function_with_iam_permissions_management_access[_]
    contains(statement.Principal.Service, "lambda")
}

aws_issue["lambda_function_with_iam_permissions_management_access"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_role"
    statement := resource.properties.assume_role_policy.Statement[j]
    statement.Action[_] == action_lambda_function_with_iam_permissions_management_access[_]
    contains(statement.Principal.Service, "lambda")
}

lambda_function_with_iam_permissions_management_access {
    lower(input.resources[i].type) == "aws_iam_role"
    not aws_issue["lambda_function_with_iam_permissions_management_access"]
}

lambda_function_with_iam_permissions_management_access = false {
    aws_issue["lambda_function_with_iam_permissions_management_access"]
}

lambda_function_with_iam_permissions_management_access_err = "Ensure that the AWS Lambda Function instances provisioned in your AWS account don't have a risky set of permissions management access permissions to minimize security risks." {
    aws_issue["lambda_function_with_iam_permissions_management_access"]
}

lambda_function_with_iam_permissions_management_access_metadata := {
    "Policy Code": "PR-AWS-TRF-IAM-015",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that the AWS Lambda Function instances provisioned in your AWS account don't have a risky set of permissions management access permissions to minimize security risks.",
    "Policy Description": "This policy identifies IAM permissions management access permissions that are defined as risky permissions. Ensure that the AWS Lambda Function instances provisioned in your AWS account don't have a risky set of permissions management access permissions to minimize security risks.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role"
}

#
# PR-AWS-TRF-IAM-016
#

default ec2_instance_with_iam_write_access = null

action_ec2_instance_with_iam_write_access := ["iam:AddClientIDToOpenIDConnectProvider","iam:AddRoleToInstanceProfile","iam:AddUserToGroup","iam:ChangePassword","iam:CreateAccessKey","iam:CreateAccountAlias","iam:CreateGroup","iam:CreateInstanceProfile","iam:CreateLoginProfile","iam:CreateOpenIDConnectProvider","iam:CreateRole","iam:CreateSAMLProvider","iam:CreateServiceLinkedRole","iam:CreateServiceSpecificCredential","iam:CreateUser","iam:CreateVirtualMFADevice","iam:DeactivateMFADevice","iam:DeleteAccessKey","iam:DeleteAccountAlias","iam:DeleteGroup","iam:DeleteInstanceProfile","iam:DeleteLoginProfile","iam:DeleteOpenIDConnectProvider","iam:DeleteRole","iam:DeleteSAMLProvider","iam:DeleteSSHPublicKey","iam:DeleteServerCertificate","iam:DeleteServiceLinkedRole","iam:DeleteServiceSpecificCredential","iam:DeleteSigningCertificate","iam:DeleteUser","iam:DeleteVirtualMFADevice","iam:EnableMFADevice","iam:PassRole","iam:RemoveClientIDFromOpenIDConnectProvider","iam:RemoveRoleFromInstanceProfile","iam:RemoveUserFromGroup","iam:ResetServiceSpecificCredential","iam:ResyncMFADevice","iam:SetSecurityTokenServicePreferences","iam:UpdateAccessKey","iam:UpdateAccountPasswordPolicy","iam:UpdateGroup","iam:UpdateLoginProfile","iam:UpdateOpenIDConnectProviderThumbprint","iam:UpdateRole","iam:UpdateRoleDescription","iam:UpdateSAMLProvider","iam:UpdateSSHPublicKey","iam:UpdateServerCertificate","iam:UpdateServiceSpecificCredential","iam:UpdateSigningCertificate","iam:UpdateUser","iam:UploadSSHPublicKey","iam:UploadServerCertificate","iam:UploadSigningCertificate"]

aws_issue["ec2_instance_with_iam_write_access"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_role"
    statement := resource.properties.assume_role_policy.Statement[j]
    statement.Action[_] == action_ec2_instance_with_iam_write_access[_]
    services := statement.Principal.Service[_]
    contains(services, "ec2")
}

aws_issue["ec2_instance_with_iam_write_access"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_role"
    statement := resource.properties.assume_role_policy.Statement[j]
    statement.Action == action_ec2_instance_with_iam_write_access[_]        
    services := statement.Principal.Service[_]
    contains(services, "ec2")
}

aws_issue["ec2_instance_with_iam_write_access"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_role"
    statement := resource.properties.assume_role_policy.Statement[j]
    statement.Action == action_ec2_instance_with_iam_write_access[_]
    contains(statement.Principal.Service, "ec2")
}

aws_issue["ec2_instance_with_iam_write_access"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_role"
    statement := resource.properties.assume_role_policy.Statement[j]
    statement.Action[_] == action_ec2_instance_with_iam_write_access[_]
    contains(statement.Principal.Service, "ec2")
}

ec2_instance_with_iam_write_access {
    lower(input.resources[i].type) == "aws_iam_role"
    not aws_issue["ec2_instance_with_iam_write_access"]
}

ec2_instance_with_iam_write_access = false {
    aws_issue["ec2_instance_with_iam_write_access"]
}

ec2_instance_with_iam_write_access_err = "Ensure that the AWS EC2 instances provisioned in your AWS account don't have a risky set of write permissions to minimize security risks." {
    aws_issue["ec2_instance_with_iam_write_access"]
}

ec2_instance_with_iam_write_access_metadata := {
    "Policy Code": "PR-AWS-TRF-IAM-016",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that the AWS EC2 instances provisioned in your AWS account don't have a risky set of write permissions to minimize security risks.",
    "Policy Description": "This policy identifies IAM write permissions that are defined as risky permissions. Ensure that the AWS EC2 instances provisioned in your AWS account don't have a risky set of write permissions to minimize security risks.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role"
}

#
# PR-AWS-TRF-IAM-017
#

default lambda_function_with_org_write_access = null

action_lambda_function_with_org_write_access := ["organizations:AcceptHandshake","organizations:AttachPolicy","organizations:CancelHandshake","organizations:CreateAccount","organizations:CreateGovCloudAccount","organizations:CreateOrganization","organizations:CreateOrganizationalUnit","organizations:CreatePolicy","organizations:DeclineHandshake","organizations:DeleteOrganization","organizations:DeleteOrganizationalUnit","organizations:DeletePolicy","organizations:DeregisterDelegatedAdministrator","organizations:DetachPolicy","organizations:DisableAWSServiceAccess","organizations:DisablePolicyType","organizations:EnableAWSServiceAccess","organizations:EnableAllFeatures","organizations:EnablePolicyType","organizations:InviteAccountToOrganization","organizations:LeaveOrganization","organizations:MoveAccount","organizations:RegisterDelegatedAdministrator","organizations:RemoveAccountFromOrganization","organizations:UpdateOrganizationalUnit","organizations:UpdatePolicy"]

aws_issue["lambda_function_with_org_write_access"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_role"
    statement := resource.properties.assume_role_policy.Statement[j]
    statement.Action[_] == action_lambda_function_with_org_write_access[_]
    services := statement.Principal.Service[_]
    contains(services, "lambda")
}

aws_issue["lambda_function_with_org_write_access"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_role"
    statement := resource.properties.assume_role_policy.Statement[j]
    statement.Action == action_lambda_function_with_org_write_access[_]        
    services := statement.Principal.Service[_]
    contains(services, "lambda")
}

aws_issue["lambda_function_with_org_write_access"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_role"
    statement := resource.properties.assume_role_policy.Statement[j]
    statement.Action == action_lambda_function_with_org_write_access[_]
    contains(statement.Principal.Service, "lambda")
}

aws_issue["lambda_function_with_org_write_access"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_role"
    statement := resource.properties.assume_role_policy.Statement[j]
    statement.Action[_] == action_lambda_function_with_org_write_access[_]
    contains(statement.Principal.Service, "lambda")
}

lambda_function_with_org_write_access {
    lower(input.resources[i].type) == "aws_iam_role"
    not aws_issue["lambda_function_with_org_write_access"]
}

lambda_function_with_org_write_access = false {
    aws_issue["lambda_function_with_org_write_access"]
}

lambda_function_with_org_write_access_err = "Ensure that the AWS Lambda Function instances provisioned in your AWS account don't have a risky set of org write permissions to minimize security risks." {
    aws_issue["lambda_function_with_org_write_access"]
}

lambda_function_with_org_write_access_metadata := {
    "Policy Code": "PR-AWS-TRF-IAM-017",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that the AWS Lambda Function instances provisioned in your AWS account don't have a risky set of org write permissions to minimize security risks.",
    "Policy Description": "This policy identifies org write access that is defined as risky permissions. Ensure that the AWS Lambda Function instances provisioned in your AWS account don't have a risky set of org write permissions to minimize security risks.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role"
}

#
# PR-AWS-TRF-IAM-018
#

default elasticbeanstalk_platform_with_iam_wildcard_resource_access = null

aws_issue["elasticbeanstalk_platform_with_iam_wildcard_resource_access"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_role"
    statement := resource.properties.assume_role_policy.Statement[j]
    policy_resource := statement.Resource[_]
    lower(policy_resource) == "*"
    services := statement.Principal.Service[_]
    contains(services, "elasticbeanstalk")
}

aws_issue["elasticbeanstalk_platform_with_iam_wildcard_resource_access"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_role"
    statement := resource.properties.assume_role_policy.Statement[j]
    lower(statement.Resource) == "*"
    services := statement.Principal.Service[_]
    contains(services, "elasticbeanstalk")
}


aws_issue["elasticbeanstalk_platform_with_iam_wildcard_resource_access"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_role"
    statement := resource.properties.assume_role_policy.Statement[j]
    policy_resource := statement.Resource[_]
    lower(policy_resource) == "*"
    contains(statement.Principal.Service, "elasticbeanstalk")
}

aws_issue["elasticbeanstalk_platform_with_iam_wildcard_resource_access"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_role"
    statement := resource.properties.assume_role_policy.Statement[j]
    lower(statement.Resource) == "*"
    contains(statement.Principal.Service, "elasticbeanstalk")
}

elasticbeanstalk_platform_with_iam_wildcard_resource_access {
    lower(input.resources[i].type) == "aws_iam_role"
    not aws_issue["elasticbeanstalk_platform_with_iam_wildcard_resource_access"]
}

elasticbeanstalk_platform_with_iam_wildcard_resource_access = false {
    aws_issue["elasticbeanstalk_platform_with_iam_wildcard_resource_access"]
}

elasticbeanstalk_platform_with_iam_wildcard_resource_access_err = "Ensure that the AWS policies don't have '*' in the resource section of the policy statement of elastic bean stalk." {
    aws_issue["elasticbeanstalk_platform_with_iam_wildcard_resource_access"]
}

elasticbeanstalk_platform_with_iam_wildcard_resource_access_metadata := {
    "Policy Code": "PR-AWS-TRF-IAM-018",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that the AWS policies don't have '*' in the resource section of the policy statement of elastic bean stalk.",
    "Policy Description": "It identifies AWS IAM permissions that contain '*' in the resource section of the policy statement of elastic bean stalk. The policy will identify those '*' only in case using '*' is not mandatory.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role"
}

#
# PR-AWS-TRF-IAM-019
#

default ec2_with_iam_wildcard_resource_access = null

aws_issue["ec2_with_iam_wildcard_resource_access"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_role"
    statement := resource.properties.assume_role_policy.Statement[j]
    policy_resource := statement.Resource[_]
    lower(policy_resource) == "*"
    services := statement.Principal.Service[_]
    contains(services, "ec2")
}

aws_issue["ec2_with_iam_wildcard_resource_access"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_role"
    statement := resource.properties.assume_role_policy.Statement[j]
    lower(statement.Resource) == "*"
    services := statement.Principal.Service[_]
    contains(services, "ec2")
}


aws_issue["ec2_with_iam_wildcard_resource_access"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_role"
    statement := resource.properties.assume_role_policy.Statement[j]
    policy_resource := statement.Resource[_]
    lower(policy_resource) == "*"
    contains(statement.Principal.Service, "ec2")
}

aws_issue["ec2_with_iam_wildcard_resource_access"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_role"
    statement := resource.properties.assume_role_policy.Statement[j]
    lower(statement.Resource) == "*"
    contains(statement.Principal.Service, "ec2")
}

ec2_with_iam_wildcard_resource_access {
    lower(input.resources[i].type) == "aws_iam_role"
    not aws_issue["ec2_with_iam_wildcard_resource_access"]
}

ec2_with_iam_wildcard_resource_access = false {
    aws_issue["ec2_with_iam_wildcard_resource_access"]
}

ec2_with_iam_wildcard_resource_access_err = "Ensure that the AWS policies don't have '*' in the resource section of the policy statement of ec2." {
    aws_issue["ec2_with_iam_wildcard_resource_access"]
}

ec2_with_iam_wildcard_resource_access_metadata := {
    "Policy Code": "PR-AWS-TRF-IAM-019",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that the AWS policies don't have '*' in the resource section of the policy statement of ec2.",
    "Policy Description": "This policy identifies AWS IAM permissions that contain '*' in the resource section of the policy statement of ec2. The policy will identify those '*' only in case using '*' is not mandatory.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role"
}

#
# PR-AWS-TRF-IAM-020
#

default lambda_function_with_iam_wildcard_resource_access = null

aws_issue["lambda_function_with_iam_wildcard_resource_access"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_role"
    statement := resource.properties.assume_role_policy.Statement[j]
    policy_resource := statement.Resource[_]
    lower(policy_resource) == "*"
    services := statement.Principal.Service[_]
    contains(services, "lambda")
}

aws_issue["lambda_function_with_iam_wildcard_resource_access"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_role"
    statement := resource.properties.assume_role_policy.Statement[j]
    lower(statement.Resource) == "*"
    services := statement.Principal.Service[_]
    contains(services, "lambda")
}


aws_issue["lambda_function_with_iam_wildcard_resource_access"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_role"
    statement := resource.properties.assume_role_policy.Statement[j]
    policy_resource := statement.Resource[_]
    lower(policy_resource) == "*"
    contains(statement.Principal.Service, "lambda")
}

aws_issue["lambda_function_with_iam_wildcard_resource_access"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_role"
    statement := resource.properties.assume_role_policy.Statement[j]
    lower(statement.Resource) == "*"
    contains(statement.Principal.Service, "lambda")
}

lambda_function_with_iam_wildcard_resource_access {
    lower(input.resources[i].type) == "aws_iam_role"
    not aws_issue["lambda_function_with_iam_wildcard_resource_access"]
}

lambda_function_with_iam_wildcard_resource_access = false {
    aws_issue["lambda_function_with_iam_wildcard_resource_access"]
}

lambda_function_with_iam_wildcard_resource_access_err = "Ensure that the AWS policies don't have '*' in the resource section of the policy statement of lambda function." {
    aws_issue["lambda_function_with_iam_wildcard_resource_access"]
}

lambda_function_with_iam_wildcard_resource_access_metadata := {
    "Policy Code": "PR-AWS-TRF-IAM-020",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that the AWS policies don't have '*' in the resource section of the policy statement of lambda function.",
    "Policy Description": "This policy identifies AWS IAM permissions that contain '*' in the resource section of the policy statement of lambda function. The policy will identify those '*' only in case using '*' is not mandatory.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role"
}

#
# PR-AWS-TRF-IAM-021
#

default ecs_task_definition_with_iam_wildcard_resource_access = null

aws_issue["ecs_task_definition_with_iam_wildcard_resource_access"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_role"
    statement := resource.properties.assume_role_policy.Statement[j]
    policy_resource := statement.Resource[_]
    lower(policy_resource) == "*"
    services := statement.Principal.Service[_]
    contains(services, "ecs")
}

aws_issue["ecs_task_definition_with_iam_wildcard_resource_access"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_role"
    statement := resource.properties.assume_role_policy.Statement[j]
    lower(statement.Resource) == "*"
    services := statement.Principal.Service[_]
    contains(services, "ecs")
}


aws_issue["ecs_task_definition_with_iam_wildcard_resource_access"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_role"
    statement := resource.properties.assume_role_policy.Statement[j]
    policy_resource := statement.Resource[_]
    lower(policy_resource) == "*"
    contains(statement.Principal.Service, "ecs")
}

aws_issue["ecs_task_definition_with_iam_wildcard_resource_access"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_role"
    statement := resource.properties.assume_role_policy.Statement[j]
    lower(statement.Resource) == "*"
    contains(statement.Principal.Service, "ecs")
}

ecs_task_definition_with_iam_wildcard_resource_access {
    lower(input.resources[i].type) == "aws_iam_role"
    not aws_issue["ecs_task_definition_with_iam_wildcard_resource_access"]
}

ecs_task_definition_with_iam_wildcard_resource_access = false {
    aws_issue["ecs_task_definition_with_iam_wildcard_resource_access"]
}

ecs_task_definition_with_iam_wildcard_resource_access_err = "Ensure that the AWS policies don't have '*' in the resource section of the policy statement of ecs task definition." {
    aws_issue["ecs_task_definition_with_iam_wildcard_resource_access"]
}

ecs_task_definition_with_iam_wildcard_resource_access_metadata := {
    "Policy Code": "PR-AWS-TRF-IAM-021",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that the AWS policies don't have '*' in the resource section of the policy statement of ecs task definition.",
    "Policy Description": "This policy identifies AWS IAM permissions that contain '*' in the resource section of the policy statement of ecs task definition. The policy will identify those '*' only in case using '*' is not mandatory.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role"
}

#
# PR-AWS-TRF-IAM-022
#

default ecr_repository_is_publicly_accessible_through_iam_policies = null

aws_issue["ecr_repository_is_publicly_accessible_through_iam_policies"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_role"
    statement := resource.properties.assume_role_policy.Statement[j]
    contains(lower(statement.Principal.Service), "ecr")
    has_property(statement.Condition[string], iam_policies_condition[_])
}

aws_issue["ecr_repository_is_publicly_accessible_through_iam_policies"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_role"
    statement := resource.properties.assume_role_policy.Statement[j]
    services := statement.Principal.Service[_]
    contains(lower(services), "ecr")
    has_property(statement.Condition[string], iam_policies_condition[_])
}

ecr_repository_is_publicly_accessible_through_iam_policies {
    lower(input.resources[i].type) == "aws_iam_role"
    not aws_issue["ecr_repository_is_publicly_accessible_through_iam_policies"]
}

ecr_repository_is_publicly_accessible_through_iam_policies = false {
    aws_issue["ecr_repository_is_publicly_accessible_through_iam_policies"]
}

ecr_repository_is_publicly_accessible_through_iam_policies_err = "Ensure that the AWS ECR Repository resources provisioned in your AWS account are not publicly accessible from the Internet to avoid sensitive data exposure and minimize security risks." {
    aws_issue["ecr_repository_is_publicly_accessible_through_iam_policies"]
}

ecr_repository_is_publicly_accessible_through_iam_policies_metadata := {
    "Policy Code": "PR-AWS-TRF-IAM-022",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that the AWS ECR Repository resources provisioned in your AWS account are not publicly accessible from the Internet to avoid sensitive data exposure and minimize security risks.",
    "Policy Description": "It identifies the AWS ECR Repository resources which are publicly accessible through IAM policies. Ensure that the AWS ECR Repository resources provisioned in your AWS account are not publicly accessible from the Internet to avoid sensitive data exposure and minimize security risks.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role"
}

#
# PR-AWS-TRF-IAM-023
#

default lambda_function_is_publicly_accessible_through_iam_policies = null

aws_issue["lambda_function_is_publicly_accessible_through_iam_policies"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_role"
    statement := resource.properties.assume_role_policy.Statement[j]
    contains(lower(statement.Principal.Service), "lambda")
    has_property(statement.Condition[string], iam_policies_condition[_])
}

aws_issue["lambda_function_is_publicly_accessible_through_iam_policies"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_role"
    statement := resource.properties.assume_role_policy.Statement[j]
    services := statement.Principal.Service[_]
    contains(lower(services), "lambda")
    has_property(statement.Condition[string], iam_policies_condition[_])
}

lambda_function_is_publicly_accessible_through_iam_policies {
    lower(input.resources[i].type) == "aws_iam_role"
    not aws_issue["lambda_function_is_publicly_accessible_through_iam_policies"]
}

lambda_function_is_publicly_accessible_through_iam_policies = false {
    aws_issue["lambda_function_is_publicly_accessible_through_iam_policies"]
}

lambda_function_is_publicly_accessible_through_iam_policies_err = "Ensure that the AWS Lambda Function resources provisioned in your AWS account are not publicly accessible from the Internet to avoid sensitive data exposure and minimize security risks." {
    aws_issue["lambda_function_is_publicly_accessible_through_iam_policies"]
}

lambda_function_is_publicly_accessible_through_iam_policies_metadata := {
    "Policy Code": "PR-AWS-TRF-IAM-023",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that the AWS Lambda Function resources provisioned in your AWS account are not publicly accessible from the Internet to avoid sensitive data exposure and minimize security risks.",
    "Policy Description": "This policy identifies the AWS Lambda Function resources which are publicly accessible through IAM policies. Ensure that the AWS Lambda Function resources provisioned in your AWS account are not publicly accessible from the Internet to avoid sensitive data exposure and minimize security risks.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role"
}

#
# PR-AWS-TRF-IAM-024
#

default s3_bucket_is_publicly_accessible_through_iam_policies = null

aws_issue["s3_bucket_is_publicly_accessible_through_iam_policies"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_role"
    statement := resource.properties.assume_role_policy.Statement[j]
    contains(lower(statement.Principal.Service), "s3")
    has_property(statement.Condition[string], iam_policies_condition[_])
}

aws_issue["s3_bucket_is_publicly_accessible_through_iam_policies"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_role"
    statement := resource.properties.assume_role_policy.Statement[j]
    services := statement.Principal.Service[_]
    contains(lower(services), "s3")
    has_property(statement.Condition[string], iam_policies_condition[_])
}

s3_bucket_is_publicly_accessible_through_iam_policies {
    lower(input.resources[i].type) == "aws_iam_role"
    not aws_issue["s3_bucket_is_publicly_accessible_through_iam_policies"]
}

s3_bucket_is_publicly_accessible_through_iam_policies = false {
    aws_issue["s3_bucket_is_publicly_accessible_through_iam_policies"]
}

s3_bucket_is_publicly_accessible_through_iam_policies_err = "Ensure that the AWS S3 bucket resources provisioned in your AWS account are not publicly accessible from the Internet to avoid sensitive data exposure and minimize security risks." {
    aws_issue["s3_bucket_is_publicly_accessible_through_iam_policies"]
}

s3_bucket_is_publicly_accessible_through_iam_policies_metadata := {
    "Policy Code": "PR-AWS-TRF-IAM-024",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that the AWS S3 bucket resources provisioned in your AWS account are not publicly accessible from the Internet to avoid sensitive data exposure and minimize security risks.",
    "Policy Description": "This policy identifies the AWS S3 bucket resources which are publicly accessible through IAM policies. Ensure that the AWS S3 bucket resources provisioned in your AWS account are not publicly accessible from the Internet to avoid sensitive data exposure and minimize security risks.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role"
}

#
# PR-AWS-TRF-IAM-025
#

default sqs_queue_is_publicly_accessible_through_iam_policies = null

condition_for_sqs := ["aws:SourceArn", "aws:VpcSourceIp", "aws:username", "aws:userid", "aws:SourceVpc", "aws:SourceVpce", "aws:SourceIp", "aws:SourceIdentity", "aws:SourceAccount", "aws:PrincipalOrgID", "aws:PrincipalArn", "aws:SourceOwner", "kms:CallerAccount", "kms:PrincipalOrgPaths", "aws:ResourceOrgID", "aws:ResourceOrgPaths", "aws:ResourceAccount"]

aws_issue["sqs_queue_is_publicly_accessible_through_iam_policies"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_role"
    statement := resource.properties.assume_role_policy.Statement[j]
    contains(lower(statement.Principal.Service), "sqs")
    has_property(statement.Condition[string], condition_for_sqs[_])
}

aws_issue["sqs_queue_is_publicly_accessible_through_iam_policies"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_role"
    statement := resource.properties.assume_role_policy.Statement[j]
    services := statement.Principal.Service[_]
    contains(lower(services), "sqs")
    has_property(statement.Condition[string], condition_for_sqs[_])
}

sqs_queue_is_publicly_accessible_through_iam_policies {
    lower(input.resources[i].type) == "aws_iam_role"
    not aws_issue["sqs_queue_is_publicly_accessible_through_iam_policies"]
}

sqs_queue_is_publicly_accessible_through_iam_policies = false {
    aws_issue["sqs_queue_is_publicly_accessible_through_iam_policies"]
}

sqs_queue_is_publicly_accessible_through_iam_policies_err = "Ensure that the AWS SQS Queue resources provisioned in your AWS account are not publicly accessible from the Internet to avoid sensitive data exposure and minimize security risks." {
    aws_issue["sqs_queue_is_publicly_accessible_through_iam_policies"]
}

sqs_queue_is_publicly_accessible_through_iam_policies_metadata := {
    "Policy Code": "PR-AWS-TRF-IAM-025",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that the AWS SQS Queue resources provisioned in your AWS account are not publicly accessible from the Internet to avoid sensitive data exposure and minimize security risks.",
    "Policy Description": "This policy identifies the AWS SQS Queue resources which are publicly accessible through IAM policies. Ensure that the AWS SQS Queue resources provisioned in your AWS account are not publicly accessible from the Internet to avoid sensitive data exposure and minimize security risks.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role"
}

#
# PR-AWS-TRF-IAM-026
#

default secret_manager_secret_is_publicly_accessible_through_iam_policies = null

aws_issue["secret_manager_secret_is_publicly_accessible_through_iam_policies"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_role"
    statement := resource.properties.assume_role_policy.Statement[j]
    contains(lower(statement.Principal.Service), "secretsmanager")
    has_property(statement.Condition[string], iam_policies_condition[_])
}

aws_issue["secret_manager_secret_is_publicly_accessible_through_iam_policies"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_role"
    statement := resource.properties.assume_role_policy.Statement[j]
    services := statement.Principal.Service[_]
    contains(lower(services), "secretsmanager")
    has_property(statement.Condition[string], iam_policies_condition[_])
}

secret_manager_secret_is_publicly_accessible_through_iam_policies {
    lower(input.resources[i].type) == "aws_iam_role"
    not aws_issue["secret_manager_secret_is_publicly_accessible_through_iam_policies"]
}

secret_manager_secret_is_publicly_accessible_through_iam_policies = false {
    aws_issue["secret_manager_secret_is_publicly_accessible_through_iam_policies"]
}

secret_manager_secret_is_publicly_accessible_through_iam_policies_err = "Ensure that the AWS Secret Manager Secret resources provisioned in your AWS account are not publicly accessible from the Internet to avoid sensitive data exposure and minimize security risks." {
    aws_issue["secret_manager_secret_is_publicly_accessible_through_iam_policies"]
}

secret_manager_secret_is_publicly_accessible_through_iam_policies_metadata := {
    "Policy Code": "PR-AWS-TRF-IAM-026",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that the AWS Secret Manager Secret resources provisioned in your AWS account are not publicly accessible from the Internet to avoid sensitive data exposure and minimize security risks.",
    "Policy Description": "This policy identifies the AWS Secret Manager Secret resources which are publicly accessible through IAM policies. Ensure that the AWS Secret Manager Secret resources provisioned in your AWS account are not publicly accessible from the Internet to avoid sensitive data exposure and minimize security risks.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role"
}

#
# PR-AWS-TRF-IAM-027
#

default iam_policy_permission_may_cause_privilege_escalation = null

action_iam_policy_permission_may_cause_privilege_escalation := ["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion", "iam:PassRole", "iam:CreateAccessKey", "iam:CreateLoginProfile", "iam:UpdateLoginProfile", "iam:AttachUserPolicy", "iam:AttachGroupPolicy", "iam:AttachRolePolicy", "iam:PutUserPolicy", "iam:PutGroupPolicy", "iam:PutRolePolicy", "iam:AddUserToGroup", "iam:UpdateAssumeRolePolicy", "iam:*"]

aws_issue["iam_policy_permission_may_cause_privilege_escalation"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_policy"
    statement := resource.properties.policy.Statement[j]
    lower(statement.Effect) == "allow"
    statement.Action[_] == action_iam_policy_permission_may_cause_privilege_escalation[_]
}

aws_issue["iam_policy_permission_may_cause_privilege_escalation"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_policy"
    statement := resource.properties.policy.Statement[j]
    lower(statement.Effect) == "allow"
    statement.Action[_] == action_iam_policy_permission_may_cause_privilege_escalation[_]
}

iam_policy_permission_may_cause_privilege_escalation {
    lower(input.resources[i].type) == "aws_iam_policy"
    not aws_issue["iam_policy_permission_may_cause_privilege_escalation"]
}

iam_policy_permission_may_cause_privilege_escalation = false {
    aws_issue["iam_policy_permission_may_cause_privilege_escalation"]
}

iam_policy_permission_may_cause_privilege_escalation_err = "Ensure AWS IAM policy do not have permission which may cause privilege escalation." {
    aws_issue["iam_policy_permission_may_cause_privilege_escalation"]
}

iam_policy_permission_may_cause_privilege_escalation_metadata := {
    "Policy Code": "PR-AWS-TRF-IAM-027",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure AWS IAM policy do not have permission which may cause privilege escalation.",
    "Policy Description": "It identifies AWS IAM Policy which have permission that may cause privilege escalation. AWS IAM policy having weak permissions could be exploited by an attacker to elevate privileges. It is recommended to follow the principle of least privileges ensuring that AWS IAM policy does not have these sensitive permissions.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy"
}


#
# PR-AWS-TRF-IAM-045
#

default sns_publicly_accessible_through_iam_policies = null

sns_condition := ["aws:SourceArn", "aws:VpcSourceIp", "aws:username", "aws:userid", "aws:SourceVpc", "aws:SourceVpce", "aws:SourceIp", "aws:SourceIdentity", "aws:SourceAccount", "aws:PrincipalOrgID", "aws:PrincipalArn", "aws:SourceOwner", "kms:CallerAccount", "kms:PrincipalOrgPaths", "aws:ResourceOrgID", "aws:ResourceOrgPaths", "aws:ResourceAccount"]

aws_issue["sns_publicly_accessible_through_iam_policies"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_role"
    statement := resource.properties.assume_role_policy.Statement[j]
    contains(lower(statement.Principal.Service), "sns")
    has_property(statement.Condition[string], sns_condition[_])
}

aws_issue["sns_publicly_accessible_through_iam_policies"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_iam_role"
    statement := resource.properties.assume_role_policy.Statement[j]
    services := statement.Principal.Service[_]
    contains(lower(services), "sns")
    has_property(statement.Condition[string], sns_condition[_])
}

sns_publicly_accessible_through_iam_policies {
    lower(input.resources[i].type) == "aws_iam_role"
    not aws_issue["sns_publicly_accessible_through_iam_policies"]
}

sns_publicly_accessible_through_iam_policies = false {
    aws_issue["sns_publicly_accessible_through_iam_policies"]
}

sns_publicly_accessible_through_iam_policies_err = "Ensure AWS SNS Topic is not publicly accessible through IAM policies." {
    aws_issue["sns_publicly_accessible_through_iam_policies"]
}

sns_publicly_accessible_through_iam_policies_metadata := {
    "Policy Code": "PR-AWS-TRF-IAM-045",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure AWS SNS Topic is not publicly accessible through IAM policies.",
    "Policy Description": "It identifies the AWS SNS Topic resources which are publicly accessible through IAM policies. Ensure that the AWS SNS Topic resources provisioned in your AWS account are not publicly accessible from the Internet to avoid sensitive data exposure and minimize security risks.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role"
}