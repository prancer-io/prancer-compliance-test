package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/AWS_IAM.html
#
# PR-AWS-CFR-IAM-001
#
default iam_wildcard_resource = null

aws_issue["iam_wildcard_resource"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::iam::policy"
    statement := resource.Properties.PolicyDocument.Statement[j]
    lower(statement.Resource) == "*"
}

source_path[{"iam_wildcard_resource": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::iam::policy"
    statement := resource.Properties.PolicyDocument.Statement[j]
    lower(statement.Resource) == "*"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "PolicyDocument", "Statement", j, "Resource"]
        ],
    }
}

iam_wildcard_resource {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::iam::policy"
    not aws_issue["iam_wildcard_resource"]
}


iam_wildcard_resource_err = "Ensure no wildcards are specified in IAM policy with 'Resource' section" {
    aws_issue["iam_wildcard_resource"]
}

iam_wildcard_resource_metadata := {
    "Policy Code": "PR-AWS-CFR-IAM-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure no wildcards are specified in IAM policy with 'Resource' section",
    "Policy Description": "Using a wildcard in the Resource element in a role's trust policy would allow any IAM user in an account to access all Resources. This is a significant security gap and can be used to gain access to sensitive data.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html"
}

#
# PR-AWS-CFR-IAM-002
#
default iam_wildcard_action = null

aws_issue["iam_wildcard_action"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::iam::managedpolicy"
    statement := resource.Properties.PolicyDocument.Statement[j]
    lower(statement.Action) == "*"
}

source_path[{"iam_wildcard_action": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::iam::managedpolicy"
    statement := resource.Properties.PolicyDocument.Statement[j]
    lower(statement.Action) == "*"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "PolicyDocument", "Statement", j, "Action"]
        ],
    }
}

aws_issue["iam_wildcard_action"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::iam::policy"
    statement := resource.Properties.PolicyDocument.Statement[j]
    lower(statement.Action) == "*"
}

source_path[{"iam_wildcard_action": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::iam::policy"
    statement := resource.Properties.PolicyDocument.Statement[j]
    lower(statement.Action) == "*"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "PolicyDocument", "Statement", j, "Action"]
        ],
    }
}

iam_wildcard_action {
    lower(input.Resources[i].Type) == "aws::iam::managedpolicy"
    not aws_issue["iam_wildcard_action"]
}

iam_wildcard_action = false {
    aws_issue["iam_wildcard_action"]
}

iam_wildcard_action_err = "Ensure no wildcards are specified in IAM policy with 'Action' section" {
    aws_issue["iam_wildcard_action"]
}

iam_wildcard_action_metadata := {
    "Policy Code": "PR-AWS-CFR-IAM-002",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure no wildcards are specified in IAM policy with 'Action' section",
    "Policy Description": "Using a wildcard in the Action element in a role's trust policy would allow any IAM user in an account to Manage all resources and a user can manipulate data. This is a significant security gap and can be used to gain access to sensitive data.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html"
}



#
# PR-AWS-CFR-IAM-003
#
default iam_wildcard_principal = null

aws_issue["iam_wildcard_principal"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::iam::role"
    statement := resource.Properties.AssumeRolePolicyDocument.Statement[j]
    lower(statement.Principal) == "*"
}

aws_issue["iam_wildcard_principal"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::iam::role"
    statement := resource.Properties.AssumeRolePolicyDocument.Statement[j]
    lower(statement.Principal.AWS) == "*"
}

source_path[{"iam_wildcard_principal": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::iam::role"
    statement := resource.Properties.AssumeRolePolicyDocument.Statement[j]
    lower(statement.Principal) == "*"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "PolicyDocument", "Statement", j, "Principal"]
        ],
    }
}

source_path[{"iam_wildcard_principal": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::iam::role"
    statement := resource.Properties.AssumeRolePolicyDocument.Statement[j]
    lower(statement.Principal.AWS) == "*"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "PolicyDocument", "Statement", j, "Principal", "AWS"]
        ],
    }
}

iam_wildcard_principal {
    lower(input.Resources[i].Type) == "aws::iam::role"
    not aws_issue["iam_wildcard_principal"]
}

iam_wildcard_principal = false {
    aws_issue["iam_wildcard_principal"]
}

iam_wildcard_principal_err = "Ensure no wildcards are specified in IAM trust-relationship policy with 'Principal' section" {
    aws_issue["iam_wildcard_principal"]
}

iam_wildcard_principal_metadata := {
    "Policy Code": "PR-AWS-CFR-IAM-003",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure no wildcards are specified in IAM trust-relationship policy with 'Principal' section",
    "Policy Description": "Using a wildcard in the Principal element in a role's trust policy would allow any IAM user in any account to access the role. This is a significant security gap and can be used to gain access to sensitive data.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-role.html"
}


#
# PR-AWS-CFR-IAM-004
#
default iam_resource_format = null

aws_issue["iam_resource_format"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::iam::role"
    statement := resource.Properties.AssumeRolePolicyDocument.Statement[j]
    lower(statement.Resource) == "arn:aws:*:*"
}

source_path[{"iam_resource_format": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::iam::role"
    statement := resource.Properties.AssumeRolePolicyDocument.Statement[j]
    lower(statement.Resource) == "arn:aws:*:*"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "AssumeRolePolicyDocument", "Statement", j, "Resource"]
        ],
    }
}

aws_issue["iam_resource_format"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::iam::user"
    policy := resource.Properties.Policies[_]
    statement := policy.PolicyDocument.Statement[j]
    lower(statement.Resource) == "arn:aws:*:*"
}

source_path[{"iam_resource_format": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::iam::user"
    policy := resource.Properties.Policies[_]
    statement := policy.PolicyDocument.Statement[j]
    lower(statement.Resource) == "arn:aws:*:*"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "PolicyDocument", "Statement", j, "Resource"]
        ],
    }
}

aws_issue["iam_resource_format"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::iam::group"
    policy := resource.Properties.Policies[_]
    statement := policy.PolicyDocument.Statement[j]
    lower(statement.Resource) == "arn:aws:*:*"
}

source_path[{"iam_resource_format": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::iam::group"
    policy := resource.Properties.Policies[_]
    statement := policy.PolicyDocument.Statement[j]
    lower(statement.Resource) == "arn:aws:*:*"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "PolicyDocument", "Statement", j, "Resource"]
        ],
    }
}

iam_resource_format {
    lower(input.Resources[i].Type) == "aws::iam::managedpolicy"
    not aws_issue["iam_resource_format"]
}

iam_resource_format = false {
    aws_issue["iam_resource_format"]
}

iam_resource_format_err = "Ensure no IAM policy has a resource specified in the following format:'arn:aws:*:*'" {
    aws_issue["iam_resource_format"]
}

iam_resource_format_metadata := {
    "Policy Code": "PR-AWS-CFR-IAM-004",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure no IAM policy has a resource specified in the following format:'arn:aws:*:*'",
    "Policy Description": "Ensure no IAM policy has a resource specified in the following format:'arn:aws:*:*' AWS only allows fully qualified ARNs or '*'. The above mentioned ARN is not supported in an identity-based policy",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html"
}


#
# PR-AWS-CFR-IAM-005
#
default iam_assume_permission = null

aws_issue["iam_assume_permission"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::iam::policy"
    statement := resource.Properties.PolicyDocument.Statement[j]
    lower(statement.Effect) == "allow"
    contains(lower(statement.Action), "sts:assumerole")
    statement.Condition == "*"
}

source_path[{"iam_assume_permission": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::iam::policy"
    statement := resource.Properties.PolicyDocument.Statement[j]
    lower(statement.Effect) == "allow"
    contains(lower(statement.Action), "sts:assumerole")
    statement.Condition == "*"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "PolicyDocument", "Statement", j, "Condition"]
        ],
    }
}

aws_issue["iam_assume_permission"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::iam::policy"
    statement := resource.Properties.PolicyDocument.Statement[j]
    lower(statement.Effect) == "allow"
    contains(lower(statement.Action), "sts:assumerole")
    not statement.Condition
}

source_path[{"iam_assume_permission": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::iam::policy"
    statement := resource.Properties.PolicyDocument.Statement[j]
    lower(statement.Effect) == "allow"
    contains(lower(statement.Action), "sts:assumerole")
    not statement.Condition
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "PolicyDocument", "Statement", j, "Condition"]
        ],
    }
}

iam_assume_permission {
    lower(input.Resources[i].Type) == "aws::iam::policy"
    not aws_issue["iam_assume_permission"]
}

iam_assume_permission = false {
    aws_issue["iam_assume_permission"]
}

iam_assume_permission_err = "AWS IAM policy allows assume role permission across all services" {
    aws_issue["iam_assume_permission"]
}

iam_assume_permission_metadata := {
    "Policy Code": "PR-AWS-CFR-IAM-005",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS IAM policy allows assume role permission across all services",
    "Policy Description": "This policy identifies AWS IAM policy which allows assume role permission across all services. Typically, AssumeRole is used if you have multiple accounts and need to access resources from each account then you can create long term credentials in one account and then use temporary security credentials to access all the other accounts by assuming roles in those accounts.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html"
}

#
# PR-AWS-CFR-IAM-006
#
default iam_all_traffic = null

aws_issue["iam_all_traffic"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::iam::policy"
    statement := resource.Properties.PolicyDocument.Statement[j]
    source_ip := statement.Condition["ForAnyValue:IpAddress"]["aws:SourceIp"][k]
    lower(source_ip) == "0.0.0.0/0"
}

source_path[{"iam_all_traffic": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::iam::policy"
    statement := resource.Properties.PolicyDocument.Statement[j]
    source_ip := statement.Condition["ForAnyValue:IpAddress"]["aws:SourceIp"][k]
    lower(source_ip) == "0.0.0.0/0"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "PolicyDocument", "Statement", j, "Condition", "ForAnyValue:IpAddress", "aws:SourceIp", k]
        ],
    }
}

iam_all_traffic {
    lower(input.Resources[i].Type) == "aws::iam::policy"
    not aws_issue["iam_all_traffic"]
}

iam_all_traffic = false {
    aws_issue["iam_all_traffic"]
}

iam_all_traffic_err = "AWS IAM policy is overly permissive to all traffic via condition clause" {
    aws_issue["iam_all_traffic"]
}

iam_all_traffic_metadata := {
    "Policy Code": "PR-AWS-CFR-IAM-006",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS IAM policy is overly permissive to all traffic via condition clause",
    "Policy Description": "This policy identifies IAM policies that have a policy that is overly permissive to all traffic via condition clause. If any IAM policy statement with a condition containing 0.0.0.0/0 or ::/0, it allows all traffic to resources attached to that IAM policy. It is highly recommended to have the least privileged IAM policy to protect the data leakage and unauthorized access.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html"
}

#
# PR-AWS-CFR-IAM-007
#
default iam_administrative_privileges = null

aws_issue["iam_administrative_privileges"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::iam::policy"
    statement := resource.Properties.PolicyDocument.Statement[j]
    statement.Action == "*"
    statement.Resource == "*"
    lower(statement.Effect) == "allow"
}

source_path[{"iam_administrative_privileges": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::iam::policy"
    statement := resource.Properties.PolicyDocument.Statement[j]
    statement.Action == "*"
    statement.Resource == "*"
    lower(statement.Effect) == "allow"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "PolicyDocument", "Statement", j, "Effect"]
        ],
    }
}

iam_administrative_privileges {
    lower(input.Resources[i].Type) == "aws::iam::policy"
    not aws_issue["iam_administrative_privileges"]
}

iam_administrative_privileges = false {
    aws_issue["iam_administrative_privileges"]
}

iam_administrative_privileges_err = "AWS IAM policy allows full administrative privileges" {
    aws_issue["iam_administrative_privileges"]
}

iam_administrative_privileges_metadata := {
    "Policy Code": "PR-AWS-CFR-IAM-007",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS IAM policy allows full administrative privileges",
    "Policy Description": "This policy identifies IAM policies with full administrative privileges. IAM policies are the means by which privileges are granted to users, groups, or roles. It is recommended and considered a standard security advice to grant least privilege like granting only the permissions required to perform a task. Determine what users need to do and then craft policies for them that let the users perform only those tasks, instead of allowing full administrative privileges.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html"
}


#
# PR-AWS-CFR-IAM-008
#
default iam_user_group_attach = null

aws_issue["iam_user_group_attach"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::iam::usertogroupaddition"
    not resource.Properties.Users
}

source_path[{"iam_user_group_attach": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::iam::usertogroupaddition"
    not resource.Properties.Users
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "Users"]
        ],
    }
}

aws_issue["iam_user_group_attach"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::iam::usertogroupaddition"
    count(resource.Properties.Users) < 1
}

source_path[{"iam_user_group_attach": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::iam::usertogroupaddition"
    count(resource.Properties.Users) < 1
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "Users"]
        ],
    }
}

iam_user_group_attach {
    lower(input.Resources[i].Type) == "aws::iam::usertogroupaddition"
    not aws_issue["iam_user_group_attach"]
}

iam_user_group_attach = false {
    aws_issue["iam_user_group_attach"]
}

iam_user_group_attach_err = "Ensure IAM groups contains at least one IAM user" {
    aws_issue["iam_user_group_attach"]
}

iam_user_group_attach_metadata := {
    "Policy Code": "PR-AWS-CFR-IAM-008",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure IAM groups contains at least one IAM user",
    "Policy Description": "Ensure that your Amazon Identity and Access Management (IAM) users are members of at least one IAM group in order to adhere to IAM security best practices",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-addusertogroup.html"
}


#
# PR-AWS-CFR-IAM-009
#
default iam_managed_policy_wildcard_resource = null

aws_issue["iam_managed_policy_wildcard_resource"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::iam::managedpolicy"
    statement := resource.Properties.PolicyDocument.Statement[j]
    lower(statement.Resource) == "*"
}

source_path[{"iam_managed_policy_wildcard_resource": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::iam::managedpolicy"
    statement := resource.Properties.PolicyDocument.Statement[j]
    lower(statement.Resource) == "*"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "PolicyDocument", "Statement", j, "Resource"]
        ],
    }
}

iam_managed_policy_wildcard_resource {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::iam::managedpolicy"
    not aws_issue["iam_managed_policy_wildcard_resource"]
}

iam_managed_policy_wildcard_resource = false {
    aws_issue["iam_managed_policy_wildcard_resource"]
}

iam_managed_policy_wildcard_resource_err = "Ensure no wildcards are specified in IAM Managed policy with 'Resource' section" {
    aws_issue["iam_managed_policy_wildcard_resource"]
}

iam_managed_policy_wildcard_resource_metadata := {
    "Policy Code": "PR-AWS-CFR-IAM-009",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure no wildcards are specified in IAM Managed policy with 'Resource' section",
    "Policy Description": "Using a wildcard in the Resource element in a role's trust policy would allow any IAM user in an account to access all Resources. This is a significant security gap and can be used to gain access to sensitive data.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html"
}


#
# PR-AWS-CFR-IAM-010
#

default iam_role_name_check = null

invalid_name_prefixes = ["cdk", "cft"]

aws_issue["iam_role_name_check"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::iam::role"
    startswith(resource.Properties.RoleName, invalid_name_prefixes[_])
}

iam_role_name_check {
    lower(input.Resources[i].Type) == "aws::iam::role"
    not aws_issue["iam_role_name_check"]
}

iam_role_name_check = false {
    aws_issue["iam_role_name_check"]
}

iam_role_name_check_err = "IAM Roles should not have names that start with \"cdk\" or \"cft\"." {
    aws_issue["iam_role_name_check"]
}

iam_role_name_check_metadata := {
    "Policy Code": "PR-AWS-CFR-IAM-010",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "IAM Roles should not have names that start with \"cdk\" or \"cft\".",
    "Policy Description": "IAM Roles should not have RoleNames that match protected namespaces \"cdk\" or \"cft\".",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html"
}
