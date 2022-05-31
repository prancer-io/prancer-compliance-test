package rego


# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/AWS_IAM.html
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
# PR-AWS-CLD-IAM-009
#

default iam_policy_not_overly_permissive_to_all_traffic = true

ip_address = ["0.0.0.0/0", "::/0"]

iam_policy_not_overly_permissive_to_all_traffic = false {
    # lower(resource.Type) == "aws::iam::policyversion"
    version := input.Versions[_]
    lower(version.IsAttached) == "true"
    policy_document := json.unmarshal(version.Document)
    policy_statement := policy_document.Statement[i]
    policy_statement.Effect == "Allow"
    policy_statement.Condition.IpAddress["aws:SourceIp"] == ip_address[_]
    contains(lower(policy_statement.Action[_]), "lambda:")
}

iam_policy_not_overly_permissive_to_all_traffic = false {
    # lower(resource.Type) == "aws::iam::policyversion"
    version := input.Versions[_]
    lower(version.IsAttached) == "true"
    policy_document := json.unmarshal(version.Document)
    policy_statement := policy_document.Statement[i]
    policy_statement.Effect == "Allow"
    policy_statement.Condition["ForAnyValue:IpAddress"]["aws:SourceIp"] == ip_address[_]
    contains(lower(policy_statement.Action[_]), "lambda:")
}


iam_policy_not_overly_permissive_to_all_traffic_err = "Ensure Lambda IAM policy is not overly permissive to all traffic" {
    not iam_policy_not_overly_permissive_to_all_traffic
}

iam_policy_not_overly_permissive_to_all_traffic_metadata := {
    "Policy Code": "PR-AWS-CLD-IAM-009",
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
# PR-AWS-CLD-IAM-010
#

default iam_policy_not_overly_permissive_to_lambda_service = true

iam_policy_not_overly_permissive_to_lambda_service = false {
    # lower(resource.Type) == "aws::iam::policyversion"
    version := input.Versions[_]
    lower(version.IsAttached) == "true"
    policy_document := json.unmarshal(version.Document)
    policy_statement := policy_document.Statement[i]
    policy_statement.Action[_] == "lambda:*"
    policy_statement.Resource[_] == "*"
    not policy_statement.Condition
  
}

iam_policy_not_overly_permissive_to_lambda_service = false {
    # lower(resource.Type) == "aws::iam::policyversion"
    version := input.Versions[_]
    lower(version.IsAttached) == "true"
    policy_document := json.unmarshal(version.Document)
    policy_statement := policy_document.Statement[i]
    policy_statement.Action == "lambda:*"
    policy_statement.Resource == "*"
    not policy_statement.Condition
}

iam_policy_not_overly_permissive_to_lambda_service_err = "Ensure IAM policy is not overly permissive to Lambda service" {
    not iam_policy_not_overly_permissive_to_lambda_service
}

iam_policy_not_overly_permissive_to_lambda_service_metadata := {
    "Policy Code": "PR-AWS-CLD-IAM-010",
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
# PR-AWS-CLD-IAM-011
#

default ec2_instance_with_iam_permissions_management_access = true

action := ["iam:AttachGroupPolicy","iam:AttachRolePolicy","iam:AttachUserPolicy","iam:CreatePolicy","iam:CreatePolicyVersion","iam:DeleteAccountPasswordPolicy","iam:DeleteGroupPolicy","iam:DeletePolicy","iam:DeletePolicyVersion","iam:DeleteRolePermissionsBoundary","iam:DeleteRolePolicy","iam:DeleteUserPermissionsBoundary","iam:DeleteUserPolicy","iam:DetachGroupPolicy","iam:DetachRolePolicy","iam:DetachUserPolicy","iam:PutGroupPolicy","iam:PutRolePermissionsBoundary","iam:PutRolePolicy","iam:PutUserPermissionsBoundary","iam:PutUserPolicy","iam:SetDefaultPolicyVersion","iam:UpdateAssumeRolePolicy"]

ec2_instance_with_iam_permissions_management_access = false {
#     lower(resource.Type) == "aws::iam::roles"
    role_policy_document := json.unmarshal(input.Role.AssumeRolePolicyDocument)
    policy_statement := role_policy_document.Statement[i]
    policy_action := policy_statement.Action[_]
    policy_action == action[_]
}

ec2_instance_with_iam_permissions_management_access_err = "Ensure that the AWS EC2 instances don't have a risky set of permissions management access to minimize security risks." {
    not ec2_instance_with_iam_permissions_management_access
}

ec2_instance_with_iam_permissions_management_access_metadata := {
    "Policy Code": "PR-AWS-CLD-IAM-011",
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
# PR-AWS-CLD-IAM-012
#

default lambda_function_with_iam_write_access = true

action_lambda_function_with_iam_write_access := ["iam:AddClientIDToOpenIDConnectProvider","iam:AddRoleToInstanceProfile","iam:AddUserToGroup","iam:ChangePassword","iam:CreateAccessKey","iam:CreateAccountAlias","iam:CreateGroup","iam:CreateInstanceProfile","iam:CreateLoginProfile","iam:CreateOpenIDConnectProvider","iam:CreateRole","iam:CreateSAMLProvider","iam:CreateServiceLinkedRole","iam:CreateServiceSpecificCredential","iam:CreateUser","iam:CreateVirtualMFADevice","iam:DeactivateMFADevice","iam:DeleteAccessKey","iam:DeleteAccountAlias","iam:DeleteGroup","iam:DeleteInstanceProfile","iam:DeleteLoginProfile","iam:DeleteOpenIDConnectProvider","iam:DeleteRole","iam:DeleteSAMLProvider","iam:DeleteSSHPublicKey","iam:DeleteServerCertificate","iam:DeleteServiceLinkedRole","iam:DeleteServiceSpecificCredential","iam:DeleteSigningCertificate","iam:DeleteUser","iam:DeleteVirtualMFADevice","iam:EnableMFADevice","iam:PassRole","iam:RemoveClientIDFromOpenIDConnectProvider","iam:RemoveRoleFromInstanceProfile","iam:RemoveUserFromGroup","iam:ResetServiceSpecificCredential","iam:ResyncMFADevice","iam:SetSecurityTokenServicePreferences","iam:UpdateAccessKey","iam:UpdateAccountPasswordPolicy","iam:UpdateGroup","iam:UpdateLoginProfile","iam:UpdateOpenIDConnectProviderThumbprint","iam:UpdateRole","iam:UpdateRoleDescription","iam:UpdateSAMLProvider","iam:UpdateSSHPublicKey","iam:UpdateServerCertificate","iam:UpdateServiceSpecificCredential","iam:UpdateSigningCertificate","iam:UpdateUser","iam:UploadSSHPublicKey","iam:UploadServerCertificate","iam:UploadSigningCertificate"]

lambda_function_with_iam_write_access = false {
#     lower(resource.Type) == "aws::iam::roles"
    role_policy_document := json.unmarshal(input.Role.AssumeRolePolicyDocument)
    policy_statement := role_policy_document.Statement[i]
    policy_action := policy_statement.Action[_]
    policy_action == action_lambda_function_with_iam_write_access[_]
}

lambda_function_with_iam_write_access_err = "Ensure that the AWS Lambda Function instances provisioned in your AWS account don't have a risky set of write permissions to minimize security risks." {
    not lambda_function_with_iam_write_access
}

lambda_function_with_iam_write_access_metadata := {
    "Policy Code": "PR-AWS-CLD-IAM-012",
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
# PR-AWS-CLD-IAM-013
#

default lambda_function_with_iam_permissions_management_access = true

action_lambda_function_with_iam_permissions_management_access := ["iam:AttachGroupPolicy","iam:AttachRolePolicy","iam:AttachUserPolicy","iam:CreatePolicy","iam:CreatePolicyVersion","iam:DeleteAccountPasswordPolicy","iam:DeleteGroupPolicy","iam:DeletePolicy","iam:DeletePolicyVersion","iam:DeleteRolePermissionsBoundary","iam:DeleteRolePolicy","iam:DeleteUserPermissionsBoundary","iam:DeleteUserPolicy","iam:DetachGroupPolicy","iam:DetachRolePolicy","iam:DetachUserPolicy","iam:PutGroupPolicy","iam:PutRolePermissionsBoundary","iam:PutRolePolicy","iam:PutUserPermissionsBoundary","iam:PutUserPolicy","iam:SetDefaultPolicyVersion","iam:UpdateAssumeRolePolicy"]

lambda_function_with_iam_permissions_management_access = false {
#     lower(resource.Type) == "aws::iam::roles"
    role_policy_document := json.unmarshal(input.Role.AssumeRolePolicyDocument)
    policy_statement := role_policy_document.Statement[i]
    policy_action := policy_statement.Action[_]
    policy_action == action_lambda_function_with_iam_permissions_management_access[_]
}

lambda_function_with_iam_permissions_management_access_err = "Ensure that the AWS Lambda Function instances provisioned in your AWS account don't have a risky set of write permissions to minimize security risks." {
    not lambda_function_with_iam_permissions_management_access
}

lambda_function_with_iam_permissions_management_access_metadata := {
    "Policy Code": "PR-AWS-CLD-IAM-013",
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
# PR-AWS-CLD-IAM-014
#

default ec2_instance_with_iam_write_access = true

action_ec2_instance_with_iam_write_access := ["iam:AddClientIDToOpenIDConnectProvider","iam:AddRoleToInstanceProfile","iam:AddUserToGroup","iam:ChangePassword","iam:CreateAccessKey","iam:CreateAccountAlias","iam:CreateGroup","iam:CreateInstanceProfile","iam:CreateLoginProfile","iam:CreateOpenIDConnectProvider","iam:CreateRole","iam:CreateSAMLProvider","iam:CreateServiceLinkedRole","iam:CreateServiceSpecificCredential","iam:CreateUser","iam:CreateVirtualMFADevice","iam:DeactivateMFADevice","iam:DeleteAccessKey","iam:DeleteAccountAlias","iam:DeleteGroup","iam:DeleteInstanceProfile","iam:DeleteLoginProfile","iam:DeleteOpenIDConnectProvider","iam:DeleteRole","iam:DeleteSAMLProvider","iam:DeleteSSHPublicKey","iam:DeleteServerCertificate","iam:DeleteServiceLinkedRole","iam:DeleteServiceSpecificCredential","iam:DeleteSigningCertificate","iam:DeleteUser","iam:DeleteVirtualMFADevice","iam:EnableMFADevice","iam:PassRole","iam:RemoveClientIDFromOpenIDConnectProvider","iam:RemoveRoleFromInstanceProfile","iam:RemoveUserFromGroup","iam:ResetServiceSpecificCredential","iam:ResyncMFADevice","iam:SetSecurityTokenServicePreferences","iam:UpdateAccessKey","iam:UpdateAccountPasswordPolicy","iam:UpdateGroup","iam:UpdateLoginProfile","iam:UpdateOpenIDConnectProviderThumbprint","iam:UpdateRole","iam:UpdateRoleDescription","iam:UpdateSAMLProvider","iam:UpdateSSHPublicKey","iam:UpdateServerCertificate","iam:UpdateServiceSpecificCredential","iam:UpdateSigningCertificate","iam:UpdateUser","iam:UploadSSHPublicKey","iam:UploadServerCertificate","iam:UploadSigningCertificate"]

ec2_instance_with_iam_write_access = false {
#     lower(resource.Type) == "aws::iam::roles"
    role_policy_document := json.unmarshal(input.Role.AssumeRolePolicyDocument)
    policy_statement := role_policy_document.Statement[i]
    policy_action := policy_statement.Action[_]
    policy_action == action_ec2_instance_with_iam_write_access[_]
}

ec2_instance_with_iam_write_access_err = "Ensure that the AWS EC2 instances provisioned in your AWS account don't have a risky set of write permissions to minimize security risks." {
    not ec2_instance_with_iam_write_access
}

ec2_instance_with_iam_write_access_metadata := {
    "Policy Code": "PR-AWS-CLD-IAM-014",
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
# PR-AWS-CLD-IAM-015
#

default lambda_function_with_org_write_access = true

action_lambda_function_with_org_write_access := ["organizations:AcceptHandshake","organizations:AttachPolicy","organizations:CancelHandshake","organizations:CreateAccount","organizations:CreateGovCloudAccount","organizations:CreateOrganization","organizations:CreateOrganizationalUnit","organizations:CreatePolicy","organizations:DeclineHandshake","organizations:DeleteOrganization","organizations:DeleteOrganizationalUnit","organizations:DeletePolicy","organizations:DeregisterDelegatedAdministrator","organizations:DetachPolicy","organizations:DisableAWSServiceAccess","organizations:DisablePolicyType","organizations:EnableAWSServiceAccess","organizations:EnableAllFeatures","organizations:EnablePolicyType","organizations:InviteAccountToOrganization","organizations:LeaveOrganization","organizations:MoveAccount","organizations:RegisterDelegatedAdministrator","organizations:RemoveAccountFromOrganization","organizations:UpdateOrganizationalUnit","organizations:UpdatePolicy"]

lambda_function_with_org_write_access = false {
#     lower(resource.Type) == "aws::iam::roles"
    role_policy_document := json.unmarshal(input.Role.AssumeRolePolicyDocument)
    policy_statement := role_policy_document.Statement[i]
    policy_action := policy_statement.Action[_]
    policy_action == action_lambda_function_with_org_write_access[_]
}

lambda_function_with_org_write_access_err = "Ensure that the AWS Lambda Function instances provisioned in your AWS account don't have a risky set of write permissions to minimize security risks." {
    not lambda_function_with_org_write_access
}

lambda_function_with_org_write_access_metadata := {
    "Policy Code": "PR-AWS-CLD-IAM-015",
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
# PR-AWS-CLD-IAM-016
#

default elasticbeanstalk_platform_with_iam_wildcard_resource_access = true

elasticbeanstalk_platform_with_iam_wildcard_resource_access = false {
#     lower(resource.Type) == "aws::iam::roles"
    role_policy_document := json.unmarshal(input.Role.AssumeRolePolicyDocument)
    policy_statement := role_policy_document.Statement[i]
    policy_resource := policy_statement.Resource
    lower(policy_resource) == "*"
}

elasticbeanstalk_platform_with_iam_wildcard_resource_access_err = "Ensure that the AWS policies don't have '*' in the resource section of the policy statement." {
    not elasticbeanstalk_platform_with_iam_wildcard_resource_access
}

elasticbeanstalk_platform_with_iam_wildcard_resource_access_metadata := {
    "Policy Code": "PR-AWS-CLD-IAM-016",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure that the AWS policies don't have '*' in the resource section of the policy statement.",
    "Policy Description": "It identifies AWS IAM permissions that contain '*' in the resource section of the policy statement. The policy will identify those '*' only in case using '*' is not mandatory.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.get_role"
}