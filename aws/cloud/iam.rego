package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/AWS_IAM.html

has_property(parent_object, target_property) { 
	_ = parent_object[target_property]
}

iam_policies_condition := ["aws:SourceArn", "aws:VpcSourceIp", "aws:username", "aws:userid", "aws:SourceVpc", "aws:SourceIp", "aws:SourceIdentity", "aws:SourceAccount", "aws:PrincipalOrgID", "aws:PrincipalArn", "AWS:SourceOwner", "kms:CallerAccount"]

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

default iam_policy_not_overly_permissive_to_all_traffic = true

ip_address = ["0.0.0.0/0", "::/0"]

iam_policy_not_overly_permissive_to_all_traffic = false {
    # lower(resource.Type) == "aws::iam::policyversion"
    version := input.PolicyVersion
    policy_document := version.Document
    policy_statement := policy_document.Statement[i]
    lower(policy_statement.Effect) == "allow"
    policy_statement.Condition.IpAddress["aws:SourceIp"] == ip_address[_]
    contains(lower(policy_statement.Action[_]), "lambda:")
}

iam_policy_not_overly_permissive_to_all_traffic = false {
    # lower(resource.Type) == "aws::iam::policyversion"
    version := input.PolicyVersion
    policy_document := version.Document
    policy_statement := policy_document.Statement[i]
    lower(policy_statement.Effect) == "allow"
    policy_statement.Condition.IpAddress["aws:SourceIp"] == ip_address[_]
    contains(lower(policy_statement.Action), "lambda:")
}

iam_policy_not_overly_permissive_to_all_traffic = false {
    # lower(resource.Type) == "aws::iam::policyversion"
    version := input.PolicyVersion
    policy_document := version.Document
    policy_statement := policy_document.Statement[i]
    lower(policy_statement.Effect) == "allow"
    policy_statement.Condition["ForAnyValue:IpAddress"]["aws:SourceIp"] == ip_address[_]
    contains(lower(policy_statement.Action[_]), "lambda:")
}

iam_policy_not_overly_permissive_to_all_traffic = false {
    # lower(resource.Type) == "aws::iam::policyversion"
    version := input.PolicyVersion
    policy_document := version.Document
    policy_statement := policy_document.Statement[i]
    lower(policy_statement.Effect) == "allow"
    policy_statement.Condition["ForAnyValue:IpAddress"]["aws:SourceIp"] == ip_address[_]
    contains(lower(policy_statement.Action), "lambda:")
}


iam_policy_not_overly_permissive_to_all_traffic_err = "Ensure Lambda IAM policy is not overly permissive to all traffic" {
    not iam_policy_not_overly_permissive_to_all_traffic
}

iam_policy_not_overly_permissive_to_all_traffic_metadata := {
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
#     lower(resource.Type) == "aws::iam::policy"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    policy_action := policy_statement.Action[_]
    policy_action == action[_]
    services := policy_statement.Principal.Service[_]
    contains(services, "ec2")
}

ec2_instance_with_iam_permissions_management_access = false {
#     lower(resource.Type) == "aws::iam::policy"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    policy_statement.Action == action[_]
    services := policy_statement.Principal.Service[_]
    contains(services, "ec2")
}

ec2_instance_with_iam_permissions_management_access = false {
#     lower(resource.Type) == "aws::iam::policy"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    policy_action := policy_statement.Action[_]
    policy_action == action[_]
    contains(policy_statement.Principal.Service, "ec2")
}

ec2_instance_with_iam_permissions_management_access = false {
#     lower(resource.Type) == "aws::iam::policy"
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
    "Policy Description": "This policy identifies IAM permissions management access that is defined as risky permissions. Ensure that the AWS EC2 instances provisioned in your AWS account don't have a risky set of write permissions to minimize security risks.",
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
#     lower(resource.Type) == "aws::iam::policy"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    policy_action := policy_statement.Action[_]
    policy_action == action_lambda_function_with_iam_write_access[_]
    services := policy_statement.Principal.Service[_]
    contains(services, "lambda")
}

lambda_function_with_iam_write_access = false {
#     lower(resource.Type) == "aws::iam::policy"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    policy_statement.Action == action_lambda_function_with_iam_write_access[_]
    services := policy_statement.Principal.Service[_]
    contains(services, "lambda")
}

lambda_function_with_iam_write_access = false {
#     lower(resource.Type) == "aws::iam::policy"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    policy_action := policy_statement.Action[_]
    policy_action == action_lambda_function_with_iam_write_access[_]
    contains(policy_statement.Principal.Service, "lambda")
}

lambda_function_with_iam_write_access = false {
#     lower(resource.Type) == "aws::iam::policy"
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
#     lower(resource.Type) == "aws::iam::policy"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    policy_action := policy_statement.Action[_]
    policy_action == action_lambda_function_with_iam_permissions_management_access[_]
    services := policy_statement.Principal.Service[_]
    contains(services, "lambda")
}

lambda_function_with_iam_permissions_management_access = false {
    # lower(resource.Type) == "aws::iam::policy"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    policy_statement.Action == action_lambda_function_with_iam_permissions_management_access[_]
    services := policy_statement.Principal.Service[_]
    contains(services, "lambda")
}

lambda_function_with_iam_permissions_management_access = false {
#     lower(resource.Type) == "aws::iam::policy"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    policy_action := policy_statement.Action[_]
    policy_action == action_lambda_function_with_iam_permissions_management_access[_]
    contains(policy_statement.Principal.Service, "lambda")
}

lambda_function_with_iam_permissions_management_access = false {
    # lower(resource.Type) == "aws::iam::policy"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    policy_statement.Action == action_lambda_function_with_iam_permissions_management_access[_]
    contains(policy_statement.Principal.Service, "lambda")
}

lambda_function_with_iam_permissions_management_access_err = "Ensure that the AWS Lambda Function instances provisioned in your AWS account don't have a risky set of write permissions to minimize security risks." {
    not lambda_function_with_iam_permissions_management_access
}

lambda_function_with_iam_permissions_management_access_metadata := {
    "Policy Code": "PR-AWS-CLD-IAM-015",
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
# PR-AWS-CLD-IAM-016
#

default ec2_instance_with_iam_write_access = true

action_ec2_instance_with_iam_write_access := ["iam:AddClientIDToOpenIDConnectProvider","iam:AddRoleToInstanceProfile","iam:AddUserToGroup","iam:ChangePassword","iam:CreateAccessKey","iam:CreateAccountAlias","iam:CreateGroup","iam:CreateInstanceProfile","iam:CreateLoginProfile","iam:CreateOpenIDConnectProvider","iam:CreateRole","iam:CreateSAMLProvider","iam:CreateServiceLinkedRole","iam:CreateServiceSpecificCredential","iam:CreateUser","iam:CreateVirtualMFADevice","iam:DeactivateMFADevice","iam:DeleteAccessKey","iam:DeleteAccountAlias","iam:DeleteGroup","iam:DeleteInstanceProfile","iam:DeleteLoginProfile","iam:DeleteOpenIDConnectProvider","iam:DeleteRole","iam:DeleteSAMLProvider","iam:DeleteSSHPublicKey","iam:DeleteServerCertificate","iam:DeleteServiceLinkedRole","iam:DeleteServiceSpecificCredential","iam:DeleteSigningCertificate","iam:DeleteUser","iam:DeleteVirtualMFADevice","iam:EnableMFADevice","iam:PassRole","iam:RemoveClientIDFromOpenIDConnectProvider","iam:RemoveRoleFromInstanceProfile","iam:RemoveUserFromGroup","iam:ResetServiceSpecificCredential","iam:ResyncMFADevice","iam:SetSecurityTokenServicePreferences","iam:UpdateAccessKey","iam:UpdateAccountPasswordPolicy","iam:UpdateGroup","iam:UpdateLoginProfile","iam:UpdateOpenIDConnectProviderThumbprint","iam:UpdateRole","iam:UpdateRoleDescription","iam:UpdateSAMLProvider","iam:UpdateSSHPublicKey","iam:UpdateServerCertificate","iam:UpdateServiceSpecificCredential","iam:UpdateSigningCertificate","iam:UpdateUser","iam:UploadSSHPublicKey","iam:UploadServerCertificate","iam:UploadSigningCertificate"]

ec2_instance_with_iam_write_access = false {
#     lower(resource.Type) == "aws::iam::policy"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    policy_action := policy_statement.Action[_]
    policy_action == action_ec2_instance_with_iam_write_access[_]
    services := policy_statement.Principal.Service[_]
    contains(services, "ec2")
}

ec2_instance_with_iam_write_access = false {
#     lower(resource.Type) == "aws::iam::policy"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    policy_statement.Action == action_ec2_instance_with_iam_write_access[_]
    services := policy_statement.Principal.Service[_]
    contains(services, "ec2")
}

ec2_instance_with_iam_write_access = false {
#     lower(resource.Type) == "aws::iam::policy"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    policy_action := policy_statement.Action[_]
    policy_action == action_ec2_instance_with_iam_write_access[_]
    contains(policy_statement.Principal.Service, "ec2")
}

ec2_instance_with_iam_write_access = false {
#     lower(resource.Type) == "aws::iam::policy"
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
    # lower(resource.Type) == "aws::iam::policy"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    policy_action := policy_statement.Action[_]
    policy_action == action_lambda_function_with_org_write_access[_]
    services := policy_statement.Principal.Service[_]
    contains(services, "lambda")
}

lambda_function_with_org_write_access = false {
    # lower(resource.Type) == "aws::iam::policy"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    policy_statement.Action == action_lambda_function_with_org_write_access[_]
    services := policy_statement.Principal.Service[_]
    contains(services, "lambda")
}

lambda_function_with_org_write_access = false {
    # lower(resource.Type) == "aws::iam::policy"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    policy_action := policy_statement.Action[_]
    policy_action == action_lambda_function_with_org_write_access[_]
    contains(policy_statement.Principal.Service, "lambda")
}

lambda_function_with_org_write_access = false {
    # lower(resource.Type) == "aws::iam::policy"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    policy_statement.Action == action_lambda_function_with_org_write_access[_]
    contains(policy_statement.Principal.Service, "lambda")
}

lambda_function_with_org_write_access_err = "Ensure that the AWS Lambda Function instances provisioned in your AWS account don't have a risky set of write permissions to minimize security risks." {
    not lambda_function_with_org_write_access
}

lambda_function_with_org_write_access_metadata := {
    "Policy Code": "PR-AWS-CLD-IAM-017",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure that the AWS Lambda Function instances provisioned in your AWS account don't have a risky set of write permissions to minimize security risks.",
    "Policy Description": "This policy identifies org write access that is defined as risky permissions. Ensure that the AWS Lambda Function instances provisioned in your AWS account don't have a risky set of write permissions to minimize security risks.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.get_role"
}

#
# PR-AWS-CLD-IAM-018
#

default elasticbeanstalk_platform_with_iam_wildcard_resource_access = true

elasticbeanstalk_platform_with_iam_wildcard_resource_access = false {
#     lower(resource.Type) == "aws::iam::policy"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    policy_resource := policy_statement.Resource[_]
    lower(policy_resource) == "*"
    services := policy_statement.Principal.Service[_]
    contains(services, "elasticbeanstalk")
}

elasticbeanstalk_platform_with_iam_wildcard_resource_access = false {
#     lower(resource.Type) == "aws::iam::policy"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    lower(policy_statement.Resource) == "*"
    services := policy_statement.Principal.Service[_]
    contains(services, "elasticbeanstalk")
}

elasticbeanstalk_platform_with_iam_wildcard_resource_access = false {
#     lower(resource.Type) == "aws::iam::policy"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    policy_resource := policy_statement.Resource[_]
    lower(policy_resource) == "*"
    contains(policy_statement.Principal.Service, "elasticbeanstalk")
}

elasticbeanstalk_platform_with_iam_wildcard_resource_access = false {
#     lower(resource.Type) == "aws::iam::policy"
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
#     lower(resource.Type) == "aws::iam::policy"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    policy_resource := policy_statement.Resource[_]
    lower(policy_resource) == "*"
    services := policy_statement.Principal.Service[_]
    contains(services, "ec2")
}

ec2_with_iam_wildcard_resource_access = false {
#     lower(resource.Type) == "aws::iam::policy"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    lower(policy_statement.Resource) == "*"
    services := policy_statement.Principal.Service[_]
    contains(services, "ec2")
}

ec2_with_iam_wildcard_resource_access = false {
#     lower(resource.Type) == "aws::iam::policy"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    policy_resource := policy_statement.Resource[_]
    lower(policy_resource) == "*"
    contains(policy_statement.Principal.Service, "ec2")
}

ec2_with_iam_wildcard_resource_access = false {
#     lower(resource.Type) == "aws::iam::policy"
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
#     lower(resource.Type) == "aws::iam::policy"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    policy_resource := policy_statement.Resource[_]
    lower(policy_resource) == "*"
    services := policy_statement.Principal.Service[_]
    contains(services, "lambda")
}


lambda_function_with_iam_wildcard_resource_access = false {
#     lower(resource.Type) == "aws::iam::policy"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    lower(policy_statement.Resource) == "*"
    services := policy_statement.Principal.Service[_]
    contains(services, "lambda")
}

lambda_function_with_iam_wildcard_resource_access = false {
#     lower(resource.Type) == "aws::iam::policy"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    policy_resource := policy_statement.Resource[_]
    lower(policy_resource) == "*"
    contains(policy_statement.Principal.Service, "lambda")
}

lambda_function_with_iam_wildcard_resource_access = false {
#     lower(resource.Type) == "aws::iam::policy"
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
#     lower(resource.Type) == "aws::iam::policy"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    policy_resource := policy_statement.Resource[_]
    lower(policy_resource) == "*"
    services := policy_statement.Principal.Service[_]
    contains(services, "ecs")
}

ecs_task_definition_with_iam_wildcard_resource_access = false {
#     lower(resource.Type) == "aws::iam::policy"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    lower(policy_statement.Resource) == "*"
    services := policy_statement.Principal.Service[_]
    contains(services, "ecs")
}

ecs_task_definition_with_iam_wildcard_resource_access = false {
#     lower(resource.Type) == "aws::iam::policy"
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    policy_resource := policy_statement.Resource[_]
    lower(policy_resource) == "*"
    contains(policy_statement.Principal.Service, "ecs")
}

ecs_task_definition_with_iam_wildcard_resource_access = false {
#     lower(resource.Type) == "aws::iam::policy"
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
#     lower(resource.Type) == "aws::iam::policy"
    some string
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    contains(lower(policy_statement.Principal.Service), "ecr")
    has_property(policy_statement.Condition[string], iam_policies_condition[_])
}

ecr_repository_is_publicly_accessible_through_iam_policies = true {
#     lower(resource.Type) == "aws::iam::policy"
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
#     lower(resource.Type) == "aws::iam::policy"
    some string
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    contains(lower(policy_statement.Principal.Service), "lambda")
    has_property(policy_statement.Condition[string], iam_policies_condition[_])
}

lambda_function_is_publicly_accessible_through_iam_policies = true {
#     lower(resource.Type) == "aws::iam::policy"
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
#     lower(resource.Type) == "aws::iam::policy"
    some string
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    contains(lower(policy_statement.Principal.Service), "s3")
    has_property(policy_statement.Condition[string], iam_policies_condition[_])
}

s3_bucket_is_publicly_accessible_through_iam_policies = true {
#     lower(resource.Type) == "aws::iam::policy"
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
#     lower(resource.Type) == "aws::iam::policy"
    some string
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    contains(lower(policy_statement.Principal.Service), "sqs")
    has_property(policy_statement.Condition[string], iam_policies_condition[_])
}

sqs_queue_is_publicly_accessible_through_iam_policies = true {
#     lower(resource.Type) == "aws::iam::policy"
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
#     lower(resource.Type) == "aws::iam::policy"
    some string
    role_policy_document := input.Role.AssumeRolePolicyDocument
    policy_statement := role_policy_document.Statement[i]
    contains(lower(policy_statement.Principal.Service), "secretsmanager")
    has_property(policy_statement.Condition[string], iam_policies_condition[_])
}

secret_manager_secret_is_publicly_accessible_through_iam_policies = true {
#     lower(resource.Type) == "aws::iam::policy"
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