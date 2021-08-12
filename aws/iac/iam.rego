package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/AWS_IAM.html
#
# PR-AWS-0226-CFR
#
default iam_wildcard_resource = null

aws_issue["iam_wildcard_resource"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::iam::managedpolicy"
    statement := resource.Properties.PolicyDocument.Statement[_]
    lower(statement.Resource) == "*"
}

iam_wildcard_resource {
    lower(input.Resources[i].Type) == "aws::iam::managedpolicy"
    not aws_issue["iam_wildcard_resource"]
}

iam_wildcard_resource = false {
    aws_issue["iam_wildcard_resource"]
}

iam_wildcard_resource_err = "Ensure no wildcards are specified in IAM policy with 'Resource' section" {
    aws_issue["iam_wildcard_resource"]
}

iam_wildcard_resource_metadata := {
    "Policy Code": "PR-AWS-0226-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure no wildcards are specified in IAM policy with 'Resource' section",
    "Policy Description": "Ensure no wildcards are specified in IAM policy with 'Resource' section",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html"
}

#
# PR-AWS-0227-CFR
#
default iam_wildcard_action = null

aws_issue["iam_wildcard_action"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::iam::managedpolicy"
    statement := resource.Properties.PolicyDocument.Statement[_]
    lower(statement.Action) == "*"
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
    "Policy Code": "PR-AWS-0227-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure no wildcards are specified in IAM policy with 'Action' section",
    "Policy Description": "Ensure no wildcards are specified in IAM policy with 'Action' section",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html"
}



#
# PR-AWS-0228-CFR
#
default iam_wildcard_principal = null

aws_issue["iam_wildcard_principal"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::iam::role"
    statement := resource.Properties.AssumeRolePolicyDocument.Statement[_]
    lower(statement.Principal) == "*"
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
    "Policy Code": "PR-AWS-0228-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure no wildcards are specified in IAM trust-relationship policy with 'Principal' section",
    "Policy Description": "Ensure no wildcards are specified in IAM trust-relationship policy with 'Principal' section",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-role.html"
}


#
# PR-AWS-0229-CFR
#
default iam_resource_format = null

aws_issue["iam_resource_format"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::iam::role"
    statement := resource.Properties.AssumeRolePolicyDocument.Statement[_]
    lower(statement.Resource) == "arn:aws:*:*"
}

aws_issue["iam_resource_format"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::iam::user"
    policy := resource.Properties.Policies[_]
    statement := policy.PolicyDocument.Statement[_]
    lower(statement.Resource) == "arn:aws:*:*"
}

aws_issue["iam_resource_format"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::iam::group"
    policy := resource.Properties.Policies[_]
    statement := policy.PolicyDocument.Statement[_]
    lower(statement.Resource) == "arn:aws:*:*"
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
    "Policy Code": "PR-AWS-0229-CFR",
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
# PR-AWS-0230-CFR
#
default iam_assume_permission = null

aws_issue["iam_assume_permission"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::iam::policy"
    statement := resource.Properties.PolicyDocument.Statement[_]
    lower(statement.Effect) == "allow"
    contains(lower(statement.Action), "sts:assumerole")
    statement.Condition == "*"
}

aws_issue["iam_assume_permission"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::iam::policy"
    statement := resource.Properties.PolicyDocument.Statement[_]
    lower(statement.Effect) == "allow"
    contains(lower(statement.Action), "sts:assumerole")
    not statement.Condition
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
    "Policy Code": "PR-AWS-0230-CFR",
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
# PR-AWS-0231-CFR
#
default iam_all_traffic = null

aws_issue["iam_all_traffic"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::iam::policy"
    statement := resource.Properties.PolicyDocument.Statement[_]
    source_ip := statement.Condition["ForAnyValue:IpAddress"]["aws:SourceIp"][_]
    lower(source_ip) == "0.0.0.0/0"
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
    "Policy Code": "PR-AWS-0231-CFR",
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
# PR-AWS-0232-CFR
#
default iam_administrative_privileges = null

aws_issue["iam_administrative_privileges"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::iam::policy"
    statement := resource.Properties.PolicyDocument.Statement[_]
    statement.Action == "*"
    statement.Resource == "*"
    lower(statement.Effect) == "allow"
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
    "Policy Code": "PR-AWS-0232-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS IAM policy allows full administrative privileges",
    "Policy Description": "This policy identifies IAM policies with full administrative privileges. IAM policies are the means by which privileges are granted to users, groups, or roles. It is recommended and considered a standard security advice to grant least privilege like granting only the permissions required to perform a task. Determine what users need to do and then craft policies for them that let the users perform only those tasks, instead of allowing full administrative privileges.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html"
}