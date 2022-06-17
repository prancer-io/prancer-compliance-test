package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/AWS_IAM.html

has_property(parent_object, target_property) { 
	_ = parent_object[target_property]
}

iam_policies_condition := ["aws:SourceArn", "aws:VpcSourceIp", "aws:username", "aws:userid", "aws:SourceVpc", "aws:SourceIp", "aws:SourceIdentity", "aws:SourceAccount", "aws:PrincipalOrgID", "aws:PrincipalArn", "AWS:SourceOwner", "kms:CallerAccount"]
ip_address = ["0.0.0.0/0", "::/0"]
available_true_choices := ["true", true]
available_false_choices := ["false", false]

#
# PR-AWS-CLD-IAM-001
#
default iam_wildcard_resource = true

iam_wildcard_resource = false {
    # lower(resource.Type) == "aws::iam::policy"
    statement := input.PolicyVersion.Document.Statement[j]
    lower(statement.Resource) == "*"
}

iam_wildcard_resource_err = "Ensure no wildcards are specified in IAM policy with 'Resource' section" {
    not iam_wildcard_resource
}

iam_wildcard_resource_metadata := {
    "Policy Code": "PR-AWS-CLD-IAM-001",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure no wildcards are specified in IAM policy with 'Resource' section",
    "Policy Description": "Using a wildcard in the Resource element in a role's trust policy would allow any IAM user in an account to access all Resources. This is a significant security gap and can be used to gain access to sensitive data.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html"
}

#
# PR-AWS-CLD-IAM-002
#
default iam_wildcard_action = true

iam_wildcard_action = false {
    # lower(resource.Type) == "aws::iam::managedpolicy"
    statement := input.PolicyVersion.Document.Statement[j]
    lower(statement.Action) == "*"
}


iam_wildcard_action = false {
    # lower(resource.Type) == "aws::iam::policy"
    statement := input.PolicyVersion.Document.Statement[j]
    lower(statement.Action) == "*"
}

iam_wildcard_action_err = "Ensure no wildcards are specified in IAM policy with 'Action' section" {
    not iam_wildcard_action
}

iam_wildcard_action_metadata := {
    "Policy Code": "PR-AWS-CLD-IAM-002",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure no wildcards are specified in IAM policy with 'Action' section",
    "Policy Description": "Using a wildcard in the Action element in a role's trust policy would allow any IAM user in an account to Manage all resources and a user can manipulate data. This is a significant security gap and can be used to gain access to sensitive data.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html"
}



#
# PR-AWS-CLD-IAM-003
#
default iam_wildcard_principal = true

iam_wildcard_principal = false {
    # lower(resource.Type) == "aws::iam::role"
    statement := input.PolicyVersion.Document.Statement[j]
    lower(statement.Principal) == "*"
}

iam_wildcard_principal_err = "Ensure no wildcards are specified in IAM trust-relationship policy with 'Principal' section" {
    not iam_wildcard_principal
}

iam_wildcard_principal_metadata := {
    "Policy Code": "PR-AWS-CLD-IAM-003",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure no wildcards are specified in IAM trust-relationship policy with 'Principal' section",
    "Policy Description": "Using a wildcard in the Principal element in a role's trust policy would allow any IAM user in any account to access the role. This is a significant security gap and can be used to gain access to sensitive data.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-role.html"
}


#
# PR-AWS-CLD-IAM-004
#
default iam_resource_format = true

iam_resource_format = false {
    statement := input.PolicyVersion.Document.Statement[j]
    lower(statement.Resource) == "arn:aws:*:*"
}

iam_resource_format_err = "Ensure no IAM policy has a resource specified in the following format:'arn:aws:*:*'" {
    not iam_resource_format
}

iam_resource_format_metadata := {
    "Policy Code": "PR-AWS-CLD-IAM-004",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure no IAM policy has a resource specified in the following format:'arn:aws:*:*'",
    "Policy Description": "Ensure no IAM policy has a resource specified in the following format:'arn:aws:*:*' AWS only allows fully qualified ARNs or '*'. The above mentioned ARN is not supported in an identity-based policy",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html"
}



#
# PR-AWS-CLD-IAM-005
#
default iam_assume_permission = true

iam_assume_permission = false {
    # lower(resource.Type) == "aws::iam::policy"
    statement := input.PolicyVersion.Document.Statement[j]
    lower(statement.Effect) == "allow"
    contains(lower(statement.Action), "sts:assumerole")
    statement.Condition == "*"
}

iam_assume_permission = false {
    # lower(resource.Type) == "aws::iam::policy"
    statement := input.PolicyVersion.Document.Statement[j]
    lower(statement.Effect) == "allow"
    contains(lower(statement.Action), "sts:assumerole")
    not statement.Condition
}

iam_assume_permission_err = "AWS IAM policy allows assume role permission across all services" {
    not iam_assume_permission
}

iam_assume_permission_metadata := {
    "Policy Code": "PR-AWS-CLD-IAM-005",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS IAM policy allows assume role permission across all services",
    "Policy Description": "This policy identifies AWS IAM policy which allows assume role permission across all services. Typically, AssumeRole is used if you have multiple accounts and need to access resources from each account then you can create long term credentials in one account and then use temporary security credentials to access all the other accounts by assuming roles in those accounts.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html"
}

#
# PR-AWS-CLD-IAM-006
#
default iam_all_traffic = true

iam_all_traffic = false {
    # lower(resource.Type) == "aws::iam::policy"
    statement := input.PolicyVersion.Document.Statement[j]
    source_ip := statement.Condition["ForAnyValue:IpAddress"]["aws:SourceIp"][k]
    lower(source_ip) == "0.0.0.0/0"
}

iam_all_traffic_err = "AWS IAM policy is overly permissive to all traffic via condition clause" {
    not iam_all_traffic
}

iam_all_traffic_metadata := {
    "Policy Code": "PR-AWS-CLD-IAM-006",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS IAM policy is overly permissive to all traffic via condition clause",
    "Policy Description": "This policy identifies IAM policies that have a policy that is overly permissive to all traffic via condition clause. If any IAM policy statement with a condition containing 0.0.0.0/0 or ::/0, it allows all traffic to resources attached to that IAM policy. It is highly recommended to have the least privileged IAM policy to protect the data leakage and unauthorized access.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html"
}

#
# PR-AWS-CLD-IAM-007
#
default iam_administrative_privileges = true

iam_administrative_privileges = false {
    # lower(resource.Type) == "aws::iam::policy"
    statement := input.PolicyVersion.Document.Statement[j]
    statement.Action == "*"
    statement.Resource == "*"
    lower(statement.Effect) == "allow"
}

iam_administrative_privileges_err = "AWS IAM policy allows full administrative privileges" {
    not iam_administrative_privileges
}

iam_administrative_privileges_metadata := {
    "Policy Code": "PR-AWS-CLD-IAM-007",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS IAM policy allows full administrative privileges",
    "Policy Description": "This policy identifies IAM policies with full administrative privileges. IAM policies are the means by which privileges are granted to users, groups, or roles. It is recommended and considered a standard security advice to grant least privilege like granting only the permissions required to perform a task. Determine what users need to do and then craft policies for them that let the users perform only those tasks, instead of allowing full administrative privileges.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html"
}


#
# PR-AWS-CLD-IAM-008
#
default iam_user_group_attach = true

iam_user_group_attach = false {
    # lower(resource.Type) == "aws::iam::usertogroupaddition"
    not input.PolicyVersion.Document
}

iam_user_group_attach = false {
    # lower(resource.Type) == "aws::iam::usertogroupaddition"
    count(input.PolicyVersion.Document) < 1
}

iam_user_group_attach_err = "Ensure IAM groups contains at least one IAM user" {
    not iam_user_group_attach
}

iam_user_group_attach_metadata := {
    "Policy Code": "PR-AWS-CLD-IAM-008",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure IAM groups contains at least one IAM user",
    "Policy Description": "Ensure that your Amazon Identity and Access Management (IAM) users are members of at least one IAM group in order to adhere to IAM security best practices",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-addusertogroup.html"
}

#
# PR-AWS-CLD-IAM-011
#

default lambda_iam_policy_not_overly_permissive_to_all_traffic = true

lambda_iam_policy_not_overly_permissive_to_all_traffic = false {
    # lower(resource.Type) == "aws::iam::policyversion"
    version := input.PolicyVersion
    policy_document := version.Document
    policy_statement := policy_document.Statement[i]
    lower(policy_statement.Effect) == "allow"
    policy_statement.Condition.IpAddress["aws:SourceIp"] == ip_address[_]
    contains(lower(policy_statement.Action[_]), "lambda:")
}

lambda_iam_policy_not_overly_permissive_to_all_traffic = false {
    # lower(resource.Type) == "aws::iam::policyversion"
    version := input.PolicyVersion
    policy_document := version.Document
    policy_statement := policy_document.Statement[i]
    lower(policy_statement.Effect) == "allow"
    policy_statement.Condition.IpAddress["aws:SourceIp"] == ip_address[_]
    contains(lower(policy_statement.Action), "lambda:")
}

lambda_iam_policy_not_overly_permissive_to_all_traffic = false {
    # lower(resource.Type) == "aws::iam::policyversion"
    version := input.PolicyVersion
    policy_document := version.Document
    policy_statement := policy_document.Statement[i]
    lower(policy_statement.Effect) == "allow"
    policy_statement.Condition["ForAnyValue:IpAddress"]["aws:SourceIp"] == ip_address[_]
    contains(lower(policy_statement.Action[_]), "lambda:")
}

lambda_iam_policy_not_overly_permissive_to_all_traffic = false {
    # lower(resource.Type) == "aws::iam::policyversion"
    version := input.PolicyVersion
    policy_document := version.Document
    policy_statement := policy_document.Statement[i]
    lower(policy_statement.Effect) == "allow"
    policy_statement.Condition["ForAnyValue:IpAddress"]["aws:SourceIp"] == ip_address[_]
    contains(lower(policy_statement.Action), "lambda:")
}


lambda_iam_policy_not_overly_permissive_to_all_traffic_err = "Ensure Lambda IAM policy is not overly permissive to all traffic" {
    not lambda_iam_policy_not_overly_permissive_to_all_traffic
}

lambda_iam_policy_not_overly_permissive_to_all_traffic_metadata := {
    "Policy Code": "PR-AWS-CLD-IAM-011",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure Lambda IAM policy is not overly permissive to all traffic",
    "Policy Description": "Ensure that the Lambda should be granted access restrictions so that only authorized users and applications have access to the service. For more details: https://docs.aws.amazon.com/lambda/latest/dg/security-iam.html",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.list_policy_versions"
}

#
# PR-AWS-CLD-IAM-012
#

default iam_policy_not_overly_permissive_to_lambda_service = true

iam_policy_not_overly_permissive_to_lambda_service = false {
    # lower(resource.Type) == "aws::iam::policyversion"
    version := input.PolicyVersion
    policy_document := version.Document
    policy_statement := policy_document.Statement[i]
    policy_statement.Action[_] == "lambda:*"
    policy_statement.Resource[_] == "*"
    not policy_statement.Condition
}

iam_policy_not_overly_permissive_to_lambda_service = false {
    # lower(resource.Type) == "aws::iam::policyversion"
    version := input.PolicyVersion
    policy_document := version.Document
    policy_statement := policy_document.Statement[i]
    policy_statement.Action == "lambda:*"
    policy_statement.Resource[_] == "*"
    not policy_statement.Condition
}

iam_policy_not_overly_permissive_to_lambda_service = false {
    # lower(resource.Type) == "aws::iam::policyversion"
    version := input.PolicyVersion
    policy_document := version.Document
    policy_statement := policy_document.Statement[i]
    policy_statement.Action[_] == "lambda:*"
    policy_statement.Resource == "*"
    not policy_statement.Condition
}

iam_policy_not_overly_permissive_to_lambda_service = false {
    # lower(resource.Type) == "aws::iam::policyversion"
    version := input.PolicyVersion
    policy_document := version.Document
    policy_statement := policy_document.Statement[i]
    policy_statement.Action == "lambda:*"
    policy_statement.Resource == "*"
    not policy_statement.Condition
}

iam_policy_not_overly_permissive_to_lambda_service_err = "Ensure IAM policy is not overly permissive to Lambda service" {
    not iam_policy_not_overly_permissive_to_lambda_service
}

iam_policy_not_overly_permissive_to_lambda_service_metadata := {
    "Policy Code": "PR-AWS-CLD-IAM-012",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure IAM policy is not overly permissive to Lambda service",
    "Policy Description": "Ensure the principle of least privileges by ensuring that only restricted Lambda services for restricted resources.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.list_policy_versions"
}


#
# PR-AWS-CLD-IAM-013
#

default ec2_instance_with_iam_permissions_management_access = true

action := ["iam:AttachGroupPolicy","iam:AttachRolePolicy","iam:AttachUserPolicy","iam:CreatePolicy","iam:CreatePolicyVersion","iam:DeleteAccountPasswordPolicy","iam:DeleteGroupPolicy","iam:DeletePolicy","iam:DeletePolicyVersion","iam:DeleteRolePermissionsBoundary","iam:DeleteRolePolicy","iam:DeleteUserPermissionsBoundary","iam:DeleteUserPolicy","iam:DetachGroupPolicy","iam:DetachRolePolicy","iam:DetachUserPolicy","iam:PutGroupPolicy","iam:PutRolePermissionsBoundary","iam:PutRolePolicy","iam:PutUserPermissionsBoundary","iam:PutUserPolicy","iam:SetDefaultPolicyVersion","iam:UpdateAssumeRolePolicy"]

ec2_instance_with_iam_permissions_management_access = false {
#     lower(resource.Type) == "aws::iam::role"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    policy_action := policy_statement.Action[_]
    policy_action == action[_]
    services := policy_statement.Principal.Service[_]
    contains(services, "ec2")
}

ec2_instance_with_iam_permissions_management_access = false {
#     lower(resource.Type) == "aws::iam::role"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    policy_statement.Action == action[_]
    services := policy_statement.Principal.Service[_]
    contains(services, "ec2")
}

ec2_instance_with_iam_permissions_management_access = false {
#     lower(resource.Type) == "aws::iam::role"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    policy_action := policy_statement.Action[_]
    policy_action == action[_]
    contains(policy_statement.Principal.Service, "ec2")
}

ec2_instance_with_iam_permissions_management_access = false {
#     lower(resource.Type) == "aws::iam::role"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    policy_statement.Action == action[_]
    contains(policy_statement.Principal.Service, "ec2")
}

ec2_instance_with_iam_permissions_management_access_err = "Ensure that the AWS EC2 instances don't have a risky set of permissions management access to minimize security risks." {
    not ec2_instance_with_iam_permissions_management_access
}

ec2_instance_with_iam_permissions_management_access_metadata := {
    "Policy Code": "PR-AWS-CLD-IAM-013",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure that the AWS EC2 instances don't have a risky set of permissions management access to minimize security risks.",
    "Policy Description": "This policy identifies IAM permissions management access that is defined as risky permissions. Ensure that the AWS EC2 instances don't have a risky set of permissions management access to minimize security risks.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.get_role"
}

#
# PR-AWS-CLD-IAM-014
#

default lambda_function_with_iam_write_access = true

action_lambda_function_with_iam_write_access := ["iam:AddClientIDToOpenIDConnectProvider","iam:AddRoleToInstanceProfile","iam:AddUserToGroup","iam:ChangePassword","iam:CreateAccessKey","iam:CreateAccountAlias","iam:CreateGroup","iam:CreateInstanceProfile","iam:CreateLoginProfile","iam:CreateOpenIDConnectProvider","iam:CreateRole","iam:CreateSAMLProvider","iam:CreateServiceLinkedRole","iam:CreateServiceSpecificCredential","iam:CreateUser","iam:CreateVirtualMFADevice","iam:DeactivateMFADevice","iam:DeleteAccessKey","iam:DeleteAccountAlias","iam:DeleteGroup","iam:DeleteInstanceProfile","iam:DeleteLoginProfile","iam:DeleteOpenIDConnectProvider","iam:DeleteRole","iam:DeleteSAMLProvider","iam:DeleteSSHPublicKey","iam:DeleteServerCertificate","iam:DeleteServiceLinkedRole","iam:DeleteServiceSpecificCredential","iam:DeleteSigningCertificate","iam:DeleteUser","iam:DeleteVirtualMFADevice","iam:EnableMFADevice","iam:PassRole","iam:RemoveClientIDFromOpenIDConnectProvider","iam:RemoveRoleFromInstanceProfile","iam:RemoveUserFromGroup","iam:ResetServiceSpecificCredential","iam:ResyncMFADevice","iam:SetSecurityTokenServicePreferences","iam:UpdateAccessKey","iam:UpdateAccountPasswordPolicy","iam:UpdateGroup","iam:UpdateLoginProfile","iam:UpdateOpenIDConnectProviderThumbprint","iam:UpdateRole","iam:UpdateRoleDescription","iam:UpdateSAMLProvider","iam:UpdateSSHPublicKey","iam:UpdateServerCertificate","iam:UpdateServiceSpecificCredential","iam:UpdateSigningCertificate","iam:UpdateUser","iam:UploadSSHPublicKey","iam:UploadServerCertificate","iam:UploadSigningCertificate"]

lambda_function_with_iam_write_access = false {
#     lower(resource.Type) == "aws::iam::role"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    policy_action := policy_statement.Action[_]
    policy_action == action_lambda_function_with_iam_write_access[_]
    services := policy_statement.Principal.Service[_]
    contains(services, "lambda")
}

lambda_function_with_iam_write_access = false {
#     lower(resource.Type) == "aws::iam::role"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    policy_statement.Action == action_lambda_function_with_iam_write_access[_]
    services := policy_statement.Principal.Service[_]
    contains(services, "lambda")
}

lambda_function_with_iam_write_access = false {
#     lower(resource.Type) == "aws::iam::role"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    policy_action := policy_statement.Action[_]
    policy_action == action_lambda_function_with_iam_write_access[_]
    contains(policy_statement.Principal.Service, "lambda")
}

lambda_function_with_iam_write_access = false {
#     lower(resource.Type) == "aws::iam::role"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    policy_statement.Action == action_lambda_function_with_iam_write_access[_]
    contains(policy_statement.Principal.Service, "lambda")
}

lambda_function_with_iam_write_access_err = "Ensure that the AWS Lambda Function instances provisioned in your AWS account don't have a risky set of write permissions to minimize security risks." {
    not lambda_function_with_iam_write_access
}

lambda_function_with_iam_write_access_metadata := {
    "Policy Code": "PR-AWS-CLD-IAM-014",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure that the AWS Lambda Function instances provisioned in your AWS account don't have a risky set of write permissions to minimize security risks.",
    "Policy Description": "This policy identifies IAM write permissions that are defined as risky permissions. Ensure that the AWS Lambda Function instances provisioned in your AWS account don't have a risky set of write permissions to minimize security risks.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.get_role"
}

#
# PR-AWS-CLD-IAM-015
#

default lambda_function_with_iam_permissions_management_access = true

action_lambda_function_with_iam_permissions_management_access := ["iam:AttachGroupPolicy","iam:AttachRolePolicy","iam:AttachUserPolicy","iam:CreatePolicy","iam:CreatePolicyVersion","iam:DeleteAccountPasswordPolicy","iam:DeleteGroupPolicy","iam:DeletePolicy","iam:DeletePolicyVersion","iam:DeleteRolePermissionsBoundary","iam:DeleteRolePolicy","iam:DeleteUserPermissionsBoundary","iam:DeleteUserPolicy","iam:DetachGroupPolicy","iam:DetachRolePolicy","iam:DetachUserPolicy","iam:PutGroupPolicy","iam:PutRolePermissionsBoundary","iam:PutRolePolicy","iam:PutUserPermissionsBoundary","iam:PutUserPolicy","iam:SetDefaultPolicyVersion","iam:UpdateAssumeRolePolicy"]

lambda_function_with_iam_permissions_management_access = false {
#     lower(resource.Type) == "aws::iam::role"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    policy_action := policy_statement.Action[_]
    policy_action == action_lambda_function_with_iam_permissions_management_access[_]
    services := policy_statement.Principal.Service[_]
    contains(services, "lambda")
}

lambda_function_with_iam_permissions_management_access = false {
    # lower(resource.Type) == "aws::iam::role"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    policy_statement.Action == action_lambda_function_with_iam_permissions_management_access[_]
    services := policy_statement.Principal.Service[_]
    contains(services, "lambda")
}

lambda_function_with_iam_permissions_management_access = false {
#     lower(resource.Type) == "aws::iam::role"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    policy_action := policy_statement.Action[_]
    policy_action == action_lambda_function_with_iam_permissions_management_access[_]
    contains(policy_statement.Principal.Service, "lambda")
}

lambda_function_with_iam_permissions_management_access = false {
    # lower(resource.Type) == "aws::iam::role"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    policy_statement.Action == action_lambda_function_with_iam_permissions_management_access[_]
    contains(policy_statement.Principal.Service, "lambda")
}

lambda_function_with_iam_permissions_management_access_err = "Ensure that the AWS Lambda Function instances provisioned in your AWS account don't have a risky set of permissions management access permissions to minimize security risks." {
    not lambda_function_with_iam_permissions_management_access
}

lambda_function_with_iam_permissions_management_access_metadata := {
    "Policy Code": "PR-AWS-CLD-IAM-015",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure that the AWS Lambda Function instances provisioned in your AWS account don't have a risky set of permissions management access permissions to minimize security risks.",
    "Policy Description": "This policy identifies IAM permissions management access permissions that are defined as risky permissions. Ensure that the AWS Lambda Function instances provisioned in your AWS account don't have a risky set of permissions management access permissions to minimize security risks.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.get_role"
}

#
# PR-AWS-CLD-IAM-016
#

default ec2_instance_with_iam_write_access = true

action_ec2_instance_with_iam_write_access := ["iam:AddClientIDToOpenIDConnectProvider","iam:AddRoleToInstanceProfile","iam:AddUserToGroup","iam:ChangePassword","iam:CreateAccessKey","iam:CreateAccountAlias","iam:CreateGroup","iam:CreateInstanceProfile","iam:CreateLoginProfile","iam:CreateOpenIDConnectProvider","iam:CreateRole","iam:CreateSAMLProvider","iam:CreateServiceLinkedRole","iam:CreateServiceSpecificCredential","iam:CreateUser","iam:CreateVirtualMFADevice","iam:DeactivateMFADevice","iam:DeleteAccessKey","iam:DeleteAccountAlias","iam:DeleteGroup","iam:DeleteInstanceProfile","iam:DeleteLoginProfile","iam:DeleteOpenIDConnectProvider","iam:DeleteRole","iam:DeleteSAMLProvider","iam:DeleteSSHPublicKey","iam:DeleteServerCertificate","iam:DeleteServiceLinkedRole","iam:DeleteServiceSpecificCredential","iam:DeleteSigningCertificate","iam:DeleteUser","iam:DeleteVirtualMFADevice","iam:EnableMFADevice","iam:PassRole","iam:RemoveClientIDFromOpenIDConnectProvider","iam:RemoveRoleFromInstanceProfile","iam:RemoveUserFromGroup","iam:ResetServiceSpecificCredential","iam:ResyncMFADevice","iam:SetSecurityTokenServicePreferences","iam:UpdateAccessKey","iam:UpdateAccountPasswordPolicy","iam:UpdateGroup","iam:UpdateLoginProfile","iam:UpdateOpenIDConnectProviderThumbprint","iam:UpdateRole","iam:UpdateRoleDescription","iam:UpdateSAMLProvider","iam:UpdateSSHPublicKey","iam:UpdateServerCertificate","iam:UpdateServiceSpecificCredential","iam:UpdateSigningCertificate","iam:UpdateUser","iam:UploadSSHPublicKey","iam:UploadServerCertificate","iam:UploadSigningCertificate"]

ec2_instance_with_iam_write_access = false {
#     lower(resource.Type) == "aws::iam::role"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    policy_action := policy_statement.Action[_]
    policy_action == action_ec2_instance_with_iam_write_access[_]
    services := policy_statement.Principal.Service[_]
    contains(services, "ec2")
}

ec2_instance_with_iam_write_access = false {
#     lower(resource.Type) == "aws::iam::role"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    policy_statement.Action == action_ec2_instance_with_iam_write_access[_]
    services := policy_statement.Principal.Service[_]
    contains(services, "ec2")
}

ec2_instance_with_iam_write_access = false {
#     lower(resource.Type) == "aws::iam::role"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    policy_action := policy_statement.Action[_]
    policy_action == action_ec2_instance_with_iam_write_access[_]
    contains(policy_statement.Principal.Service, "ec2")
}

ec2_instance_with_iam_write_access = false {
#     lower(resource.Type) == "aws::iam::role"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    policy_statement.Action == action_ec2_instance_with_iam_write_access[_]
    contains(policy_statement.Principal.Service, "ec2")
}

ec2_instance_with_iam_write_access_err = "Ensure that the AWS EC2 instances provisioned in your AWS account don't have a risky set of write permissions to minimize security risks." {
    not ec2_instance_with_iam_write_access
}

ec2_instance_with_iam_write_access_metadata := {
    "Policy Code": "PR-AWS-CLD-IAM-016",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure that the AWS EC2 instances provisioned in your AWS account don't have a risky set of write permissions to minimize security risks.",
    "Policy Description": "This policy identifies IAM write permissions that are defined as risky permissions. Ensure that the AWS EC2 instances provisioned in your AWS account don't have a risky set of write permissions to minimize security risks.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.get_role"
}

#
# PR-AWS-CLD-IAM-017
#

default lambda_function_with_org_write_access = true

action_lambda_function_with_org_write_access := ["organizations:AcceptHandshake","organizations:AttachPolicy","organizations:CancelHandshake","organizations:CreateAccount","organizations:CreateGovCloudAccount","organizations:CreateOrganization","organizations:CreateOrganizationalUnit","organizations:CreatePolicy","organizations:DeclineHandshake","organizations:DeleteOrganization","organizations:DeleteOrganizationalUnit","organizations:DeletePolicy","organizations:DeregisterDelegatedAdministrator","organizations:DetachPolicy","organizations:DisableAWSServiceAccess","organizations:DisablePolicyType","organizations:EnableAWSServiceAccess","organizations:EnableAllFeatures","organizations:EnablePolicyType","organizations:InviteAccountToOrganization","organizations:LeaveOrganization","organizations:MoveAccount","organizations:RegisterDelegatedAdministrator","organizations:RemoveAccountFromOrganization","organizations:UpdateOrganizationalUnit","organizations:UpdatePolicy"]

lambda_function_with_org_write_access = false {
    # lower(resource.Type) == "aws::iam::role"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    policy_action := policy_statement.Action[_]
    policy_action == action_lambda_function_with_org_write_access[_]
    services := policy_statement.Principal.Service[_]
    contains(services, "lambda")
}

lambda_function_with_org_write_access = false {
    # lower(resource.Type) == "aws::iam::role"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    policy_statement.Action == action_lambda_function_with_org_write_access[_]
    services := policy_statement.Principal.Service[_]
    contains(services, "lambda")
}

lambda_function_with_org_write_access = false {
    # lower(resource.Type) == "aws::iam::role"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    policy_action := policy_statement.Action[_]
    policy_action == action_lambda_function_with_org_write_access[_]
    contains(policy_statement.Principal.Service, "lambda")
}

lambda_function_with_org_write_access = false {
    # lower(resource.Type) == "aws::iam::role"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    policy_statement.Action == action_lambda_function_with_org_write_access[_]
    contains(policy_statement.Principal.Service, "lambda")
}

lambda_function_with_org_write_access_err = "Ensure that the AWS Lambda Function instances provisioned in your AWS account don't have a risky set of org write permissions to minimize security risks." {
    not lambda_function_with_org_write_access
}

lambda_function_with_org_write_access_metadata := {
    "Policy Code": "PR-AWS-CLD-IAM-017",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure that the AWS Lambda Function instances provisioned in your AWS account don't have a risky set of org write permissions to minimize security risks.",
    "Policy Description": "This policy identifies org write access that is defined as risky permissions. Ensure that the AWS Lambda Function instances provisioned in your AWS account don't have a risky set of org write permissions to minimize security risks.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.get_role"
}

#
# PR-AWS-CLD-IAM-018
#

default elasticbeanstalk_platform_with_iam_wildcard_resource_access = true

elasticbeanstalk_platform_with_iam_wildcard_resource_access = false {
#     lower(resource.Type) == "aws::iam::role"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    policy_resource := policy_statement.Resource[_]
    lower(policy_resource) == "*"
    services := policy_statement.Principal.Service[_]
    contains(services, "elasticbeanstalk")
}

elasticbeanstalk_platform_with_iam_wildcard_resource_access = false {
#     lower(resource.Type) == "aws::iam::role"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    lower(policy_statement.Resource) == "*"
    services := policy_statement.Principal.Service[_]
    contains(services, "elasticbeanstalk")
}

elasticbeanstalk_platform_with_iam_wildcard_resource_access = false {
#     lower(resource.Type) == "aws::iam::role"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    policy_resource := policy_statement.Resource[_]
    lower(policy_resource) == "*"
    contains(policy_statement.Principal.Service, "elasticbeanstalk")
}

elasticbeanstalk_platform_with_iam_wildcard_resource_access = false {
#     lower(resource.Type) == "aws::iam::role"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    lower(policy_statement.Resource) == "*"
    contains(policy_statement.Principal.Service, "elasticbeanstalk")
}

elasticbeanstalk_platform_with_iam_wildcard_resource_access_err = "Ensure that the AWS policies don't have '*' in the resource section of the policy statement of elastic bean stalk." {
    not elasticbeanstalk_platform_with_iam_wildcard_resource_access
}

elasticbeanstalk_platform_with_iam_wildcard_resource_access_metadata := {
    "Policy Code": "PR-AWS-CLD-IAM-018",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure that the AWS policies don't have '*' in the resource section of the policy statement of elastic bean stalk.",
    "Policy Description": "It identifies AWS IAM permissions that contain '*' in the resource section of the policy statement of elastic bean stalk. The policy will identify those '*' only in case using '*' is not mandatory.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.get_role"
}

#
# PR-AWS-CLD-IAM-019
#

default ec2_with_iam_wildcard_resource_access = true

ec2_with_iam_wildcard_resource_access = false {
#     lower(resource.Type) == "aws::iam::role"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    policy_resource := policy_statement.Resource[_]
    lower(policy_resource) == "*"
    services := policy_statement.Principal.Service[_]
    contains(services, "ec2")
}

ec2_with_iam_wildcard_resource_access = false {
#     lower(resource.Type) == "aws::iam::role"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    lower(policy_statement.Resource) == "*"
    services := policy_statement.Principal.Service[_]
    contains(services, "ec2")
}

ec2_with_iam_wildcard_resource_access = false {
#     lower(resource.Type) == "aws::iam::role"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    policy_resource := policy_statement.Resource[_]
    lower(policy_resource) == "*"
    contains(policy_statement.Principal.Service, "ec2")
}

ec2_with_iam_wildcard_resource_access = false {
#     lower(resource.Type) == "aws::iam::role"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    lower(policy_statement.Resource) == "*"
    contains(policy_statement.Principal.Service, "ec2")
}

ec2_with_iam_wildcard_resource_access_err = "Ensure that the AWS policies don't have '*' in the resource section of the policy statement of ec2." {
    not ec2_with_iam_wildcard_resource_access
}

ec2_with_iam_wildcard_resource_access_metadata := {
    "Policy Code": "PR-AWS-CLD-IAM-019",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure that the AWS policies don't have '*' in the resource section of the policy statement of ec2.",
    "Policy Description": "This policy identifies AWS IAM permissions that contain '*' in the resource section of the policy statement of ec2. The policy will identify those '*' only in case using '*' is not mandatory.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.get_role"
}

#
# PR-AWS-CLD-IAM-020
#

default lambda_function_with_iam_wildcard_resource_access = true

lambda_function_with_iam_wildcard_resource_access = false {
#     lower(resource.Type) == "aws::iam::role"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    policy_resource := policy_statement.Resource[_]
    lower(policy_resource) == "*"
    services := policy_statement.Principal.Service[_]
    contains(services, "lambda")
}


lambda_function_with_iam_wildcard_resource_access = false {
#     lower(resource.Type) == "aws::iam::role"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    lower(policy_statement.Resource) == "*"
    services := policy_statement.Principal.Service[_]
    contains(services, "lambda")
}

lambda_function_with_iam_wildcard_resource_access = false {
#     lower(resource.Type) == "aws::iam::role"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    policy_resource := policy_statement.Resource[_]
    lower(policy_resource) == "*"
    contains(policy_statement.Principal.Service, "lambda")
}

lambda_function_with_iam_wildcard_resource_access = false {
#     lower(resource.Type) == "aws::iam::role"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    lower(policy_statement.Resource) == "*"
    contains(policy_statement.Principal.Service, "lambda")
}

lambda_function_with_iam_wildcard_resource_access_err = "Ensure that the AWS policies don't have '*' in the resource section of the policy statement of lambda function." {
    not lambda_function_with_iam_wildcard_resource_access
}

lambda_function_with_iam_wildcard_resource_access_metadata := {
    "Policy Code": "PR-AWS-CLD-IAM-020",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure that the AWS policies don't have '*' in the resource section of the policy statement of lambda function.",
    "Policy Description": "This policy identifies AWS IAM permissions that contain '*' in the resource section of the policy statement of lambda function. The policy will identify those '*' only in case using '*' is not mandatory.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.get_role"
}

#
# PR-AWS-CLD-IAM-021
#

default ecs_task_definition_with_iam_wildcard_resource_access = true

ecs_task_definition_with_iam_wildcard_resource_access = false {
#     lower(resource.Type) == "aws::iam::role"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    policy_resource := policy_statement.Resource[_]
    lower(policy_resource) == "*"
    services := policy_statement.Principal.Service[_]
    contains(services, "ecs")
}

ecs_task_definition_with_iam_wildcard_resource_access = false {
#     lower(resource.Type) == "aws::iam::role"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    lower(policy_statement.Resource) == "*"
    services := policy_statement.Principal.Service[_]
    contains(services, "ecs")
}

ecs_task_definition_with_iam_wildcard_resource_access = false {
#     lower(resource.Type) == "aws::iam::role"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    policy_resource := policy_statement.Resource[_]
    lower(policy_resource) == "*"
    contains(policy_statement.Principal.Service, "ecs")
}

ecs_task_definition_with_iam_wildcard_resource_access = false {
#     lower(resource.Type) == "aws::iam::role"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    lower(policy_statement.Resource) == "*"
    contains(policy_statement.Principal.Service, "ecs")
}

ecs_task_definition_with_iam_wildcard_resource_access_err = "Ensure that the AWS policies don't have '*' in the resource section of the policy statement of ecs task definition." {
    not ecs_task_definition_with_iam_wildcard_resource_access
}

ecs_task_definition_with_iam_wildcard_resource_access_metadata := {
    "Policy Code": "PR-AWS-CLD-IAM-021",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure that the AWS policies don't have '*' in the resource section of the policy statement of ecs task definition.",
    "Policy Description": "This policy identifies AWS IAM permissions that contain '*' in the resource section of the policy statement of ecs task definition. The policy will identify those '*' only in case using '*' is not mandatory.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.get_role"
}

#
# PR-AWS-CLD-IAM-022
#

default ecr_repository_is_publicly_accessible_through_iam_policies = false

ecr_repository_is_publicly_accessible_through_iam_policies = true {
#     lower(resource.Type) == "aws::iam::role"
    some string
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    contains(lower(policy_statement.Principal.Service), "ecr")
    has_property(policy_statement.Condition[string], iam_policies_condition[_])
}

ecr_repository_is_publicly_accessible_through_iam_policies = true {
#     lower(resource.Type) == "aws::iam::role"
    some string
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    services := policy_statement.Principal.Service[_]
    contains(lower(services), "ecr")
    has_property(policy_statement.Condition[string], iam_policies_condition[_])
}

ecr_repository_is_publicly_accessible_through_iam_policies_err = "Ensure that the AWS ECR Repository resources provisioned in your AWS account are not publicly accessible from the Internet to avoid sensitive data exposure and minimize security risks." {
    not ecr_repository_is_publicly_accessible_through_iam_policies
}

ecr_repository_is_publicly_accessible_through_iam_policies_metadata := {
    "Policy Code": "PR-AWS-CLD-IAM-022",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure that the AWS ECR Repository resources provisioned in your AWS account are not publicly accessible from the Internet to avoid sensitive data exposure and minimize security risks.",
    "Policy Description": "It identifies the AWS ECR Repository resources which are publicly accessible through IAM policies. Ensure that the AWS ECR Repository resources provisioned in your AWS account are not publicly accessible from the Internet to avoid sensitive data exposure and minimize security risks.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.get_role"
}

#
# PR-AWS-CLD-IAM-023
#

default lambda_function_is_publicly_accessible_through_iam_policies = false

lambda_function_is_publicly_accessible_through_iam_policies = true {
#     lower(resource.Type) == "aws::iam::role"
    some string
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    contains(lower(policy_statement.Principal.Service), "lambda")
    has_property(policy_statement.Condition[string], iam_policies_condition[_])
}

lambda_function_is_publicly_accessible_through_iam_policies = true {
#     lower(resource.Type) == "aws::iam::role"
    some string
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    services := policy_statement.Principal.Service[_]
    contains(lower(services), "lambda")
    has_property(policy_statement.Condition[string], iam_policies_condition[_])
}

lambda_function_is_publicly_accessible_through_iam_policies_err = "Ensure that the AWS Lambda Function resources provisioned in your AWS account are not publicly accessible from the Internet to avoid sensitive data exposure and minimize security risks." {
    not lambda_function_is_publicly_accessible_through_iam_policies
}

lambda_function_is_publicly_accessible_through_iam_policies_metadata := {
    "Policy Code": "PR-AWS-CLD-IAM-023",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure that the AWS Lambda Function resources provisioned in your AWS account are not publicly accessible from the Internet to avoid sensitive data exposure and minimize security risks.",
    "Policy Description": "This policy identifies the AWS Lambda Function resources which are publicly accessible through IAM policies. Ensure that the AWS Lambda Function resources provisioned in your AWS account are not publicly accessible from the Internet to avoid sensitive data exposure and minimize security risks.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.get_role"
}

#
# PR-AWS-CLD-IAM-024
#

default s3_bucket_is_publicly_accessible_through_iam_policies = false

s3_bucket_is_publicly_accessible_through_iam_policies = true {
#     lower(resource.Type) == "aws::iam::role"
    some string
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    contains(lower(policy_statement.Principal.Service), "s3")
    has_property(policy_statement.Condition[string], iam_policies_condition[_])
}

s3_bucket_is_publicly_accessible_through_iam_policies = true {
#     lower(resource.Type) == "aws::iam::role"
    some string
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    services := policy_statement.Principal.Service[_]
    contains(lower(services), "s3")
    has_property(policy_statement.Condition[string], iam_policies_condition[_])
}

s3_bucket_is_publicly_accessible_through_iam_policies_err = "Ensure that the AWS S3 bucket resources provisioned in your AWS account are not publicly accessible from the Internet to avoid sensitive data exposure and minimize security risks." {
    not s3_bucket_is_publicly_accessible_through_iam_policies
}

s3_bucket_is_publicly_accessible_through_iam_policies_metadata := {
    "Policy Code": "PR-AWS-CLD-IAM-024",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure that the AWS S3 bucket resources provisioned in your AWS account are not publicly accessible from the Internet to avoid sensitive data exposure and minimize security risks.",
    "Policy Description": "This policy identifies the AWS S3 bucket resources which are publicly accessible through IAM policies. Ensure that the AWS S3 bucket resources provisioned in your AWS account are not publicly accessible from the Internet to avoid sensitive data exposure and minimize security risks.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.get_role"
}

#
# PR-AWS-CLD-IAM-025
#

default sqs_queue_is_publicly_accessible_through_iam_policies = false

sqs_queue_is_publicly_accessible_through_iam_policies = true {
#     lower(resource.Type) == "aws::iam::role"
    some string
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    contains(lower(policy_statement.Principal.Service), "sqs")
    has_property(policy_statement.Condition[string], iam_policies_condition[_])
}

sqs_queue_is_publicly_accessible_through_iam_policies = true {
#     lower(resource.Type) == "aws::iam::role"
    some string
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    services := policy_statement.Principal.Service[_]
    contains(lower(services), "sqs")
    has_property(policy_statement.Condition[string], iam_policies_condition[_])
}

sqs_queue_is_publicly_accessible_through_iam_policies_err = "Ensure that the AWS SQS Queue resources provisioned in your AWS account are not publicly accessible from the Internet to avoid sensitive data exposure and minimize security risks." {
    not sqs_queue_is_publicly_accessible_through_iam_policies
}

sqs_queue_is_publicly_accessible_through_iam_policies_metadata := {
    "Policy Code": "PR-AWS-CLD-IAM-025",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure that the AWS SQS Queue resources provisioned in your AWS account are not publicly accessible from the Internet to avoid sensitive data exposure and minimize security risks.",
    "Policy Description": "This policy identifies the AWS SQS Queue resources which are publicly accessible through IAM policies. Ensure that the AWS SQS Queue resources provisioned in your AWS account are not publicly accessible from the Internet to avoid sensitive data exposure and minimize security risks.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.get_role"
}

#
# PR-AWS-CLD-IAM-026
#

default secret_manager_secret_is_publicly_accessible_through_iam_policies = false

secret_manager_secret_is_publicly_accessible_through_iam_policies = true {
#     lower(resource.Type) == "aws::iam::role"
    some string
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    contains(lower(policy_statement.Principal.Service), "secretsmanager")
    has_property(policy_statement.Condition[string], iam_policies_condition[_])
}

secret_manager_secret_is_publicly_accessible_through_iam_policies = true {
#     lower(resource.Type) == "aws::iam::role"
    some string
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    services := policy_statement.Principal.Service[_]
    contains(lower(services), "secretsmanager")
    has_property(policy_statement.Condition[string], iam_policies_condition[_])
}

secret_manager_secret_is_publicly_accessible_through_iam_policies_err = "Ensure that the AWS Secret Manager Secret resources provisioned in your AWS account are not publicly accessible from the Internet to avoid sensitive data exposure and minimize security risks." {
    not secret_manager_secret_is_publicly_accessible_through_iam_policies
}

secret_manager_secret_is_publicly_accessible_through_iam_policies_metadata := {
    "Policy Code": "PR-AWS-CLD-IAM-026",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure that the AWS Secret Manager Secret resources provisioned in your AWS account are not publicly accessible from the Internet to avoid sensitive data exposure and minimize security risks.",
    "Policy Description": "This policy identifies the AWS Secret Manager Secret resources which are publicly accessible through IAM policies. Ensure that the AWS Secret Manager Secret resources provisioned in your AWS account are not publicly accessible from the Internet to avoid sensitive data exposure and minimize security risks.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.get_role"
}

#
# PR-AWS-CLD-IAM-027
#

default iam_policy_permission_may_cause_privilege_escalation = true

action_iam_policy_permission_may_cause_privilege_escalation := ["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion", "iam:PassRole", "iam:CreateAccessKey", "iam:CreateLoginProfile", "iam:UpdateLoginProfile", "iam:AttachUserPolicy", "iam:AttachGroupPolicy", "iam:AttachRolePolicy", "iam:PutUserPolicy", "iam:PutGroupPolicy", "iam:PutRolePolicy", "iam:AddUserToGroup", "iam:UpdateAssumeRolePolicy", "iam:*"]

iam_policy_permission_may_cause_privilege_escalation = false {
    # lower(resource.Type) == "aws::iam::policyversion"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    lower(policy_statement.Effect) == "allow"
    policy_action := policy_statement.Action[_]
    policy_action == action_iam_policy_permission_may_cause_privilege_escalation[_]
}

iam_policy_permission_may_cause_privilege_escalation = false {
    # lower(resource.Type) == "aws::iam::policyversion"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    lower(policy_statement.Effect) == "allow"
    policy_statement.Action == action_iam_policy_permission_may_cause_privilege_escalation[_]
}

iam_policy_permission_may_cause_privilege_escalation_err = "Ensure AWS IAM policy do not have permission which may cause privilege escalation." {
    not iam_policy_permission_may_cause_privilege_escalation
}

iam_policy_permission_may_cause_privilege_escalation_metadata := {
    "Policy Code": "PR-AWS-CLD-IAM-027",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS IAM policy do not have permission which may cause privilege escalation.",
    "Policy Description": "It identifies AWS IAM Policy which have permission that may cause privilege escalation. AWS IAM policy having weak permissions could be exploited by an attacker to elevate privileges. It is recommended to follow the principle of least privileges ensuring that AWS IAM policy does not have these sensitive permissions.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.get_role"
}

#
# PR-AWS-CLD-IAM-028
#

default iam_access_key_enabled_on_root_account = true

iam_access_key_enabled_on_root_account = false {
    # lower(resource.Type) == "aws::iam::policy"
    input.SummaryMap.AccountAccessKeysPresent == 0
    
}

iam_access_key_enabled_on_root_account_err = "Ensure AWS Access key is enabled on root account." {
    not iam_access_key_enabled_on_root_account
}

iam_access_key_enabled_on_root_account_metadata := {
    "Policy Code": "PR-AWS-CLD-IAM-028",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS Access key is enabled on root account.",
    "Policy Description": "It identifies that account access key is enabled or not from IAM account summary.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#accountsummary"
}

#
# PR-AWS-CLD-IAM-029
#

default iam_policy_not_overly_permissive_to_all_traffic_for_ecs= true

iam_policy_not_overly_permissive_to_all_traffic_for_ecs = false {
    # lower(resource.Type) == "aws::iam::policyversion"
    version := input.PolicyVersion
    policy_document := version.Document
    policy_statement := policy_document.Statement[i]
    lower(policy_statement.Effect) == "allow"
    policy_statement.Condition.IpAddress["aws:SourceIp"] == ip_address[_]
    startswith(lower(policy_statement.Action[_]), "ecs:")
}

iam_policy_not_overly_permissive_to_all_traffic_for_ecs = false {
    # lower(resource.Type) == "aws::iam::policyversion"
    version := input.PolicyVersion
    policy_document := version.Document
    policy_statement := policy_document.Statement[i]
    lower(policy_statement.Effect) == "allow"
    policy_statement.Condition.IpAddress["aws:SourceIp"] == ip_address[_]
    startswith(lower(policy_statement.Action), "ecs:")
}

iam_policy_not_overly_permissive_to_all_traffic_for_ecs = false {
    # lower(resource.Type) == "aws::iam::policyversion"
    version := input.PolicyVersion
    policy_document := version.Document
    policy_statement := policy_document.Statement[i]
    lower(policy_statement.Effect) == "allow"
    policy_statement.Condition["ForAnyValue:IpAddress"]["aws:SourceIp"] == ip_address[_]
    startswith(lower(policy_statement.Action[_]), "ecs:")
}

iam_policy_not_overly_permissive_to_all_traffic_for_ecs = false {
    # lower(resource.Type) == "aws::iam::policyversion"
    version := input.PolicyVersion
    policy_document := version.Document
    policy_statement := policy_document.Statement[i]
    lower(policy_statement.Effect) == "allow"
    policy_statement.Condition["ForAnyValue:IpAddress"]["aws:SourceIp"] == ip_address[_]
    startswith(lower(policy_statement.Action), "ecs:")
}


iam_policy_not_overly_permissive_to_all_traffic_for_ecs_err = "Ensure IAM policy is not overly permissive to all traffic for ecs." {
    not iam_policy_not_overly_permissive_to_all_traffic_for_ecs
}

iam_policy_not_overly_permissive_to_all_traffic_for_ecs_metadata := {
    "Policy Code": "PR-AWS-CLD-IAM-029",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure IAM policy is not overly permissive to all traffic for ecs.",
    "Policy Description": "This policy identifies ECS IAM policies that are overly permissive to all traffic. It is recommended that the ECS should be granted access restrictions so that only authorized users and applications have access to the service. For more details: https://docs.aws.amazon.com/AmazonECS/latest/userguide/security_iam_id-based-policy-examples.html#security_iam_service-with-iam-policy-best-practices",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.list_policy_versions"
}

#
# PR-AWS-CLD-IAM-030
#

default elasticsearch_iam_policy_not_overly_permissive_to_all_traffic = true

elasticsearch_iam_policy_not_overly_permissive_to_all_traffic = false {
    # lower(resource.Type) == "aws::iam::policyversion"
    version := input.PolicyVersion
    policy_document := version.Document
    policy_statement := policy_document.Statement[i]
    lower(policy_statement.Effect) == "allow"
    policy_statement.Condition.IpAddress["aws:SourceIp"] == ip_address[_]
    startswith(lower(policy_statement.Action[_]), "es:")
}

elasticsearch_iam_policy_not_overly_permissive_to_all_traffic = false {
    # lower(resource.Type) == "aws::iam::policyversion"
    version := input.PolicyVersion
    policy_document := version.Document
    policy_statement := policy_document.Statement[i]
    lower(policy_statement.Effect) == "allow"
    policy_statement.Condition.IpAddress["aws:SourceIp"] == ip_address[_]
    startswith(lower(policy_statement.Action), "es:")
}

elasticsearch_iam_policy_not_overly_permissive_to_all_traffic = false {
    # lower(resource.Type) == "aws::iam::policyversion"
    version := input.PolicyVersion
    policy_document := version.Document
    policy_statement := policy_document.Statement[i]
    lower(policy_statement.Effect) == "allow"
    policy_statement.Condition["ForAnyValue:IpAddress"]["aws:SourceIp"] == ip_address[_]
    startswith(lower(policy_statement.Action[_]), "es:")
}

elasticsearch_iam_policy_not_overly_permissive_to_all_traffic = false {
    # lower(resource.Type) == "aws::iam::policyversion"
    version := input.PolicyVersion
    policy_document := version.Document
    policy_statement := policy_document.Statement[i]
    lower(policy_statement.Effect) == "allow"
    policy_statement.Condition["ForAnyValue:IpAddress"]["aws:SourceIp"] == ip_address[_]
    startswith(lower(policy_statement.Action), "es:")
}


elasticsearch_iam_policy_not_overly_permissive_to_all_traffic_err = "Ensure IAM policy is not overly permissive to all traffic for elasticsearch." {
    not elasticsearch_iam_policy_not_overly_permissive_to_all_traffic
}

elasticsearch_iam_policy_not_overly_permissive_to_all_traffic_metadata := {
    "Policy Code": "PR-AWS-CLD-IAM-030",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure IAM policy is not overly permissive to all traffic for elasticsearch.",
    "Policy Description": "It identifies Elasticsearch IAM policies that are overly permissive to all traffic. Amazon Elasticsearch service makes it easy to deploy and manage Elasticsearch. Customers can create a domain where the service is accessible. The domain should be granted access restrictions so that only authorized users and applications have access to the service.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.list_policy_versions"
}

#
# PR-AWS-CLD-IAM-031
#

default iam_password_policy_secure = true

iam_password_policy_secure = false {
    lower(input.PasswordPolicy.RequireSymbols) == available_false_choices[_]
}

iam_password_policy_secure = false {
    lower(input.PasswordPolicy.RequireNumbers) == available_false_choices[_]
}

iam_password_policy_secure = false {
    lower(input.PasswordPolicy.ExpirePasswords) == available_false_choices[_]
}

iam_password_policy_secure = false {
    lower(input.PasswordPolicy.RequireUppercaseCharacters) == available_false_choices[_]
}

iam_password_policy_secure = false {
    lower(input.PasswordPolicy.AllowUsersToChangePassword) == available_false_choices[_]
}

iam_password_policy_secure = false {
    lower(input.PasswordPolicy.RequireUppercaseCharacters) == available_false_choices[_]
}

iam_password_policy_secure = false {
    lower(input.PasswordPolicy.RequireLowercaseCharacters) == available_false_choices[_]
}

iam_password_policy_secure = false {
    not input.PasswordPolicy.MaxPasswordAge
}

iam_password_policy_secure = false {
    not input.PasswordPolicy.PasswordReusePrevention
}

iam_password_policy_secure = false {
    to_number(input.PasswordPolicy.MinimumPasswordLength) <= 6
}

iam_password_policy_secure_err = "Ensure AWS IAM Password policy is secure." {
    not iam_password_policy_secure
}

iam_password_policy_secure_metadata := {
    "Policy Code": "PR-AWS-CLD-IAM-031",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS IAM Password policy is secure.",
    "Policy Description": "It checks to ensure that IAM password policy is in place for the cloud accounts. As a security best practice, customers must have strong password policies in place. This policy ensures password policies are set with all following options: Minimum Password Length, At least one Uppercase letter, At least one Lowercase letter, At least one Number, At least one Symbol/non-alphanumeric character, Users have permission to change their own password, Password expiration period, Password reuse and Password expiration requires administrator reset.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.get_account_password_policy"
}

#
# PR-AWS-CLD-IAM-032
#

default not_reusing_password = true

not_reusing_password = false {
    input.PasswordPolicy.PasswordReusePrevention == null
}

not_reusing_password = false {
    input.PasswordPolicy.PasswordReusePrevention == ""
}

not_reusing_password = false {
    not input.PasswordPolicy.PasswordReusePrevention
}

not_reusing_password = false {
    to_number(input.PasswordPolicy.PasswordReusePrevention) < 12
}

not_reusing_password_err = "Ensure IAM Password Policy does not allow reusing atleast last 12 passwords." {
    not not_reusing_password
}

not_reusing_password_metadata := {
    "Policy Code": "PR-AWS-CLD-IAM-032",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure IAM Password Policy does not allow reusing atleast last 12 passwords.",
    "Policy Description": "It checks to ensure that IAM password policy is in place for the cloud accounts. As a security best practice, customers must have strong password policies in place. This policy ensures password policies are set with all following options: Minimum Password Length, At least one Uppercase letter, At least one Lowercase letter, At least one Number, At least one Symbol/non-alphanumeric character, Users have permission to change their own password, Password expiration period, Password reuse and Password expiration requires administrator reset.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.get_account_password_policy"
}

#
# PR-AWS-CLD-IAM-033
#

default no_lowercase_character_password = true

no_lowercase_character_password = false {
    lower(input.PasswordPolicy.RequireLowercaseCharacters) == available_false_choices[_]
}

no_lowercase_character_password = false {
    not input.PasswordPolicy.RequireLowercaseCharacters
}

no_lowercase_character_password_err = "Ensure AWS IAM password policy have a lowercase character." {
    not no_lowercase_character_password
}

no_lowercase_character_password_metadata := {
    "Policy Code": "PR-AWS-CLD-IAM-033",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS IAM password policy have a lowercase character.",
    "Policy Description": "Checks to ensure that IAM password policy requires a lowercase character. AWS IAM (Identity & Access Management) allows customers to secure AWS console access. As a security best practice, customers must have strong password policies in place.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.get_account_password_policy"
}

#
# PR-AWS-CLD-IAM-034
#

default minimum_fourteen_character_password = true

minimum_fourteen_character_password = false {
    to_number(input.PasswordPolicy.MinimumPasswordLength) < 14
}

minimum_fourteen_character_password = false {
    not input.PasswordPolicy.MinimumPasswordLength
}

minimum_fourteen_character_password_err = "Ensure AWS IAM password policy have a minimum of 14 characters." {
    not minimum_fourteen_character_password
}

minimum_fourteen_character_password_metadata := {
    "Policy Code": "PR-AWS-CLD-IAM-034",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS IAM password policy have a minimum of 14 characters.",
    "Policy Description": "Checks to ensure that IAM password policy requires minimum of 14 characters. AWS IAM (Identity & Access Management) allows customers to secure AWS console access. As a security best practice, customers must have strong password policies in place.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.get_account_password_policy"
}

#
# PR-AWS-CLD-IAM-035
#

default password_expire_in_ninty_days = true

password_expire_in_ninty_days = false {
    to_number(input.PasswordPolicy.MaxPasswordAge) > 90
}

password_expire_in_ninty_days = false {
    input.PasswordPolicy.MaxPasswordAge == 0
}

password_expire_in_ninty_days_err = "Ensure AWS IAM password policy have password expiration set to 90 days." {
    not password_expire_in_ninty_days
}

password_expire_in_ninty_days_metadata := {
    "Policy Code": "PR-AWS-CLD-IAM-035",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS IAM password policy have password expiration set to 90 days.",
    "Policy Description": "It identifies the IAM policies which does not have password expiration set to 90 days. AWS IAM (Identity & Access Management) allows customers to secure AWS console access. As a security best practice, customers must have strong password policies in place.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.get_account_password_policy"
}

#
# PR-AWS-CLD-IAM-036
#

default password_expire_period_defined = true

password_expire_period_defined = false {
    to_number(input.PasswordPolicy.MaxPasswordAge) < 1
}

password_expire_period_defined = false {
    not input.PasswordPolicy.MaxPasswordAge
}

password_expire_period_defined_err = "Ensure AWS IAM password policy have password expiration period defined." {
    not password_expire_period_defined
}

password_expire_period_defined_metadata := {
    "Policy Code": "PR-AWS-CLD-IAM-036",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS IAM password policy have password expiration period defined.",
    "Policy Description": "It checks to ensure that IAM password policy has an expiration period. AWS IAM (Identity & Access Management) allows customers to secure AWS console access. As a security best practice, customers must have strong password policies in place.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.get_account_password_policy"
}

#
# PR-AWS-CLD-IAM-037
#

default password_have_numbers = true

password_have_numbers = false {
    lower(input.PasswordPolicy.RequireNumbers) == available_false_choices[_]
}

password_have_numbers = false {
    not input.PasswordPolicy.RequireNumbers
}

password_have_numbers_err = "Ensure AWS IAM password policy have require number equals true." {
    not password_have_numbers
}

password_have_numbers_metadata := {
    "Policy Code": "PR-AWS-CLD-IAM-037",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS IAM password policy have require number equals true.",
    "Policy Description": "It checks to ensure that IAM password policy requires a number. AWS IAM (Identity & Access Management) allows customers to secure AWS console access. As a security best practice, customers must have strong password policies in place.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.get_account_password_policy"
}

#
# PR-AWS-CLD-IAM-038
#

default password_have_symbols = true

password_have_symbols = false {
    lower(input.PasswordPolicy.RequireSymbols) == available_false_choices[_]
}

password_have_symbols = false {
    not input.PasswordPolicy.RequireSymbols
}

password_have_symbols_err = "Ensure AWS IAM password policy have require symbols equals true." {
    not password_have_symbols
}

password_have_symbols_metadata := {
    "Policy Code": "PR-AWS-CLD-IAM-038",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS IAM password policy have require symbols equals true.",
    "Policy Description": "It checks to ensure that IAM password policy requires a symbol. AWS IAM (Identity & Access Management) allows customers to secure AWS console access. As a security best practice, customers must have strong password policies in place.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.get_account_password_policy"
}

#
# PR-AWS-CLD-IAM-039
#

default password_have_upper_case_char = true

password_have_upper_case_char = false {
    lower(input.PasswordPolicy.RequireUppercaseCharacters) == available_false_choices[_]
}

password_have_upper_case_char = false {
    not input.PasswordPolicy.RequireUppercaseCharacters
}

password_have_upper_case_char_err = "Ensure AWS IAM password policy have require upper case characters equals true." {
    not password_have_upper_case_char
}

password_have_upper_case_char_metadata := {
    "Policy Code": "PR-AWS-CLD-IAM-039",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS IAM password policy have require upper case characters equals true.",
    "Policy Description": "It identifies AWS accounts in which IAM password policy does not have an uppercase character. AWS IAM (Identity & Access Management) allows customers to secure AWS console access. As a security best practice, customers must have strong password policies in place.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.get_account_password_policy"
}

#
# PR-AWS-CLD-IAM-040
#

default not_password_reuse = true

not_password_reuse = false {
    not input.PasswordPolicy.RequireUppercaseCharacters
}

not_password_reuse = false {
    to_number(input.PasswordPolicy.PasswordReusePrevention) < 1
}

not_password_reuse = false {
    input.PasswordPolicy.PasswordReusePrevention = null
}

not_password_reuse = false {
    input.PasswordPolicy.PasswordReusePrevention = ""
}

not_password_reuse_err = "Ensure AWS IAM password policy does not allow password reuse." {
    not not_password_reuse
}

not_password_reuse_metadata := {
    "Policy Code": "PR-AWS-CLD-IAM-040",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS IAM password policy does not allow password reuse.",
    "Policy Description": "It identifies IAM policies which allow password reuse. AWS IAM (Identity & Access Management) allows customers to secure AWS console access. As a security best practice, customers must have strong password policies in place.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.get_account_password_policy"
}

#
# PR-AWS-CLD-IAM-041
#

default not_allow_decryption_actions_on_all_kms_keys = true

not_allow_decryption_actions_on_all_kms_keys = false {
    # lower(resource.Type) == "aws::iam::policyversion"
    version := input.PolicyVersion
    policy_document := version.Document
    policy_statement := policy_document.Statement[i]
    lower(policy_statement.Effect) == "allow"
    policy_statement.Resource == "*"
    contains(lower(policy_statement.Action[_]), "kms:*")
    not policy_statement.Condition
}

not_allow_decryption_actions_on_all_kms_keys = false {
    # lower(resource.Type) == "aws::iam::policyversion"
    version := input.PolicyVersion
    policy_document := version.Document
    policy_statement := policy_document.Statement[i]
    lower(policy_statement.Effect) == "allow"
    policy_statement.Resource == "*"
    contains(lower(policy_statement.Action), "kms:*")
    not policy_statement.Condition
}

not_allow_decryption_actions_on_all_kms_keys = false {
    # lower(resource.Type) == "aws::iam::policyversion"
    version := input.PolicyVersion
    policy_document := version.Document
    policy_statement := policy_document.Statement[i]
    lower(policy_statement.Effect) == "allow"
    policy_statement.Resource[_]== "*"
    contains(lower(policy_statement.Action), "kms:*")
    not policy_statement.Condition
}

not_allow_decryption_actions_on_all_kms_keys = false {
    # lower(resource.Type) == "aws::iam::policyversion"
    version := input.PolicyVersion
    policy_document := version.Document
    policy_statement := policy_document.Statement[i]
    lower(policy_statement.Effect) == "allow"
    policy_statement.Resource[_] == "*"
    contains(lower(policy_statement.Action[_]), "kms:*")
    not policy_statement.Condition
}

not_allow_decryption_actions_on_all_kms_keys = false {
    # lower(resource.Type) == "aws::iam::policyversion"
    version := input.PolicyVersion
    policy_document := version.Document
    policy_statement := policy_document.Statement[i]
    lower(policy_statement.Effect) == "allow"
    policy_statement.Resource == "*"
    contains(lower(policy_statement.Action[_]), "kms:Decrypt")
    not policy_statement.Condition
}

not_allow_decryption_actions_on_all_kms_keys = false {
    # lower(resource.Type) == "aws::iam::policyversion"
    version := input.PolicyVersion
    policy_document := version.Document
    policy_statement := policy_document.Statement[i]
    lower(policy_statement.Effect) == "allow"
    policy_statement.Resource == "*"
    contains(lower(policy_statement.Action), "kms:Decrypt")
    not policy_statement.Condition
}

not_allow_decryption_actions_on_all_kms_keys = false {
    # lower(resource.Type) == "aws::iam::policyversion"
    version := input.PolicyVersion
    policy_document := version.Document
    policy_statement := policy_document.Statement[i]
    lower(policy_statement.Effect) == "allow"
    policy_statement.Resource[_]== "*"
    contains(lower(policy_statement.Action), "kms:Decrypt")
    not policy_statement.Condition
}

not_allow_decryption_actions_on_all_kms_keys = false {
    # lower(resource.Type) == "aws::iam::policyversion"
    version := input.PolicyVersion
    policy_document := version.Document
    policy_statement := policy_document.Statement[i]
    lower(policy_statement.Effect) == "allow"
    policy_statement.Resource[_] == "*"
    contains(lower(policy_statement.Action[_]), "kms:Decrypt")
    not policy_statement.Condition
}

not_allow_decryption_actions_on_all_kms_keys = false {
    # lower(resource.Type) == "aws::iam::policyversion"
    version := input.PolicyVersion
    policy_document := version.Document
    policy_statement := policy_document.Statement[i]
    lower(policy_statement.Effect) == "allow"
    policy_statement.Resource == "*"
    contains(lower(policy_statement.Action[_]), "kms:ReEncryptFrom")
    not policy_statement.Condition
}

not_allow_decryption_actions_on_all_kms_keys = false {
    # lower(resource.Type) == "aws::iam::policyversion"
    version := input.PolicyVersion
    policy_document := version.Document
    policy_statement := policy_document.Statement[i]
    lower(policy_statement.Effect) == "allow"
    policy_statement.Resource == "*"
    contains(lower(policy_statement.Action), "kms:ReEncryptFrom")
    not policy_statement.Condition
}

not_allow_decryption_actions_on_all_kms_keys = false {
    # lower(resource.Type) == "aws::iam::policyversion"
    version := input.PolicyVersion
    policy_document := version.Document
    policy_statement := policy_document.Statement[i]
    lower(policy_statement.Effect) == "allow"
    policy_statement.Resource[_]== "*"
    contains(lower(policy_statement.Action), "kms:ReEncryptFrom")
    not policy_statement.Condition
}

not_allow_decryption_actions_on_all_kms_keys = false {
    # lower(resource.Type) == "aws::iam::policyversion"
    version := input.PolicyVersion
    policy_document := version.Document
    policy_statement := policy_document.Statement[i]
    lower(policy_statement.Effect) == "allow"
    policy_statement.Resource[_] == "*"
    contains(lower(policy_statement.Action[_]), "kms:ReEncryptFrom")
    not policy_statement.Condition
}

not_allow_decryption_actions_on_all_kms_keys_err = "Ensure AWS IAM policy does not allows decryption actions on all KMS keys." {
    not not_allow_decryption_actions_on_all_kms_keys
}

not_allow_decryption_actions_on_all_kms_keys_metadata := {
    "Policy Code": "PR-AWS-CLD-IAM-041",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS IAM policy does not allows decryption actions on all KMS keys.",
    "Policy Description": "It identifies IAM policies that allow decryption actions on all KMS keys. Instead of granting permissions for all keys, determine the minimum set of keys that users need to access encrypted data. You should grant to identities only the kms:Decrypt or kms:ReEncryptFrom permissions and only for the keys that are required to perform a task. By adopting the principle of least privilege, you can reduce the risk of unintended disclosure of your data.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.list_policy_versions"
}

#
# PR-AWS-CLD-IAM-042
#

default iam_policy_attached_to_user = true

iam_policy_attached_to_user = false {
    count(input.AttachedPolicies) != 0
}

iam_policy_attached_to_user_err = "Ensure IAM policy is attached to user." {
    not iam_policy_attached_to_user
}

iam_policy_attached_to_user_metadata := {
    "Policy Code": "PR-AWS-CLD-IAM-042",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure IAM policy is attached to user.",
    "Policy Description": "It identifies IAM policies attached to user. By default, IAM users, groups, and roles have no access to AWS resources. IAM policies are the means by which privileges are granted to users, groups, or roles. It is recommended that IAM policies be applied directly to groups but not users.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.list_attached_user_policies"
}

#
# PR-AWS-CLD-IAM-043
#

default iam_policy_not_overly_permissive_to_all_traffic = true

iam_policy_not_overly_permissive_to_all_traffic = false {
    # lower(resource.Type) == "aws::iam::policyversion"
    version := input.PolicyVersion
    policy_document := version.Document
    policy_statement := policy_document.Statement[i]
    lower(policy_statement.Effect) == "allow"
    policy_statement.Condition.IpAddress["aws:SourceIp"] == ip_address[_]
    contains(lower(policy_statement.Action[_]), "*")
}

iam_policy_not_overly_permissive_to_all_traffic = false {
    # lower(resource.Type) == "aws::iam::policyversion"
    version := input.PolicyVersion
    policy_document := version.Document
    policy_statement := policy_document.Statement[i]
    lower(policy_statement.Effect) == "allow"
    policy_statement.Condition.IpAddress["aws:SourceIp"] == ip_address[_]
    contains(lower(policy_statement.Action), "*")
}

iam_policy_not_overly_permissive_to_all_traffic = false {
    # lower(resource.Type) == "aws::iam::policyversion"
    version := input.PolicyVersion
    policy_document := version.Document
    policy_statement := policy_document.Statement[i]
    lower(policy_statement.Effect) == "allow"
    policy_statement.Condition["ForAnyValue:IpAddress"]["aws:SourceIp"] == ip_address[_]
    contains(lower(policy_statement.Action[_]), "*")
}

iam_policy_not_overly_permissive_to_all_traffic = false {
    # lower(resource.Type) == "aws::iam::policyversion"
    version := input.PolicyVersion
    policy_document := version.Document
    policy_statement := policy_document.Statement[i]
    lower(policy_statement.Effect) == "allow"
    policy_statement.Condition["ForAnyValue:IpAddress"]["aws:SourceIp"] == ip_address[_]
    contains(lower(policy_statement.Action), "*")
}


iam_policy_not_overly_permissive_to_all_traffic_err = "Ensure IAM policy is not overly permissive to all traffic via condition clause." {
    not iam_policy_not_overly_permissive_to_all_traffic
}

iam_policy_not_overly_permissive_to_all_traffic_metadata := {
    "Policy Code": "PR-AWS-CLD-IAM-043",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure IAM policy is not overly permissive to all traffic via condition clause.",
    "Policy Description": "It identifies IAM policies that have a policy that is overly permissive to all traffic via condition clause. If any IAM policy statement with a condition containing 0.0.0.0/0 or ::/0, it allows all traffic to resources attached to that IAM policy. It is highly recommended to have the least privileged IAM policy to protect the data leakage and unauthorized access.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.list_policy_versions"
}

#
# PR-AWS-CLD-IAM-044
#

default iam_policy_not_overly_permissive_to_sts_service = true

iam_policy_not_overly_permissive_to_sts_service = false {
    # lower(resource.Type) == "aws::iam::policyversion"
    version := input.PolicyVersion
    policy_document := version.Document
    policy_statement := policy_document.Statement[i]
    lower(policy_statement.Effect) == "allow"
    policy_statement.Resource == "*"
    contains(lower(policy_statement.Action[_]), "sts:*")
    not policy_statement.Condition
}

iam_policy_not_overly_permissive_to_sts_service = false {
    # lower(resource.Type) == "aws::iam::policyversion"
    version := input.PolicyVersion
    policy_document := version.Document
    policy_statement := policy_document.Statement[i]
    lower(policy_statement.Effect) == "allow"
    policy_statement.Resource == "*"
    contains(lower(policy_statement.Action), "sts:*")
    not policy_statement.Condition
}

iam_policy_not_overly_permissive_to_sts_service = false {
    # lower(resource.Type) == "aws::iam::policyversion"
    version := input.PolicyVersion
    policy_document := version.Document
    policy_statement := policy_document.Statement[i]
    lower(policy_statement.Effect) == "allow"
    policy_statement.Resource[_]== "*"
    contains(lower(policy_statement.Action), "sts:*")
    not policy_statement.Condition
}

iam_policy_not_overly_permissive_to_sts_service = false {
    # lower(resource.Type) == "aws::iam::policyversion"
    version := input.PolicyVersion
    policy_document := version.Document
    policy_statement := policy_document.Statement[i]
    lower(policy_statement.Effect) == "allow"
    policy_statement.Resource[_] == "*"
    contains(lower(policy_statement.Action[_]), "sts:*")
    not policy_statement.Condition
}

iam_policy_not_overly_permissive_to_sts_service_err = "Ensure AWS IAM policy is not overly permissive to STS services." {
    not iam_policy_not_overly_permissive_to_sts_service
}

iam_policy_not_overly_permissive_to_sts_service_metadata := {
    "Policy Code": "PR-AWS-CLD-IAM-044",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS IAM policy is not overly permissive to STS services.",
    "Policy Description": "It identifies the IAM policies that are overly permissive to STS services. AWS Security Token Service (AWS STS) is a web service that enables you to request temporary credentials for AWS Identity and Access Management (IAM) users or for users that you authenticate (federated users). It is recommended to follow the principle of least privileges ensuring that only restricted STS services for restricted resources.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.list_policy_versions"
}