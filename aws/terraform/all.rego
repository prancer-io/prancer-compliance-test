package rule

available_false_choices := ["false", false]

has_property(parent_object, target_property) { 
	_ = parent_object[target_property]
}

rules_packages = [
    "arn:aws:inspector:us-east-2:646659390643:rulespackage/0-JnA8Zp85",
    "arn:aws:inspector:us-east-1:316112463485:rulespackage/0-gEjTy7T7",
    "arn:aws:inspector:us-west-1:166987590008:rulespackage/0-TKgzoVOa",
    "arn:aws:inspector:us-west-2:758058086616:rulespackage/0-9hgA516p",
    "arn:aws:inspector:ap-south-1:162588757376:rulespackage/0-LqnJE9dO",
    "arn:aws:inspector:ap-northeast-2:526946625049:rulespackage/0-PoGHMznc",
    "arn:aws:inspector:ap-southeast-2:454640832652:rulespackage/0-D5TGAxiR",
    "arn:aws:inspector:ap-northeast-1:406045910587:rulespackage/0-gHP9oWNT",
    "arn:aws:inspector:eu-central-1:537503971621:rulespackage/0-wNqHa8M9",
    "arn:aws:inspector:eu-west-1:357557129151:rulespackage/0-ubA5XvBh",
    "arn:aws:inspector:eu-west-2:146838936955:rulespackage/0-kZGCqcE1",
    "arn:aws:inspector:eu-north-1:453420244670:rulespackage/0-IgdgIewd",
    "arn:aws-us-gov:inspector:us-gov-east-1:206278770380:rulespackage/0-3IFKFuOb",
    "arn:aws-us-gov:inspector:us-gov-west-1:850862329162:rulespackage/0-4oQgcI4G"
]

#
# PR-AWS-TRF-SM-001
#

default secret_manager_kms = null

aws_issue["secret_manager_kms"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_secretsmanager_secret"
    not resource.properties.kms_key_id
}

source_path[{"secret_manager_kms": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_secretsmanager_secret"
    not resource.properties.kms_key_id
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "kms_key_id"]
        ],
    }
}

aws_issue["secret_manager_kms"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_secretsmanager_secret"
    count(resource.properties.kms_key_id) == 0
}

source_path[{"secret_manager_kms": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_secretsmanager_secret"
    count(resource.properties.kms_key_id) == 0
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "kms_key_id"]
        ],
    }
}

secret_manager_kms {
    lower(input.resources[i].type) == "aws_secretsmanager_secret"
    not aws_issue["secret_manager_kms"]
}

secret_manager_kms = false {
    aws_issue["secret_manager_kms"]
}

secret_manager_kms_err = "Ensure that Secrets Manager secret is encrypted using KMS" {
    aws_issue["secret_manager_kms"]
}

secret_manager_kms_metadata := {
    "Policy Code": "PR-AWS-TRF-SM-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that Secrets Manager secret is encrypted using KMS",
    "Policy Description": "Ensure that your Amazon Secrets Manager secrets (i.e. database credentials, API keys, OAuth tokens, etc) are encrypted with Amazon KMS Customer Master Keys instead of default encryption keys that Secrets Manager service creates for you, in order to have a more control over secret data encryption and decryption process",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-secretsmanager-secret.html"
}


#
# PR-AWS-TRF-SM-003
#

default secret_manager_automatic_rotation = null

aws_issue["secret_manager_automatic_rotation"] {
    resource_1 := input.resources[i]
    lower(resource_1.type) == "aws_secretsmanager_secret"
    secretid := resource_1.properties.name
    resource_2 := input.resources[j]
    lower(resource_2.type) == "aws_secretsmanager_secret_rotation"
    resource_2.properties.secret_id != secretid
}

aws_issue["secret_manager_automatic_rotation"] {
    resource_1 := input.resources[i]
    lower(resource_1.type) == "aws_secretsmanager_secret"
    secretid := resource_1.name
    resource_2 := input.resources[j]
    lower(resource_2.type) == "aws_secretsmanager_secret_rotation"
    resource_2.properties.secret_id != secretid
}

secret_manager_automatic_rotation {
    lower(input.resources[i].type) == "aws_secretsmanager_secret_rotation"
    not aws_issue["secret_manager_automatic_rotation"]
}

secret_manager_automatic_rotation = false {
    aws_issue["secret_manager_automatic_rotation"]
}

secret_manager_automatic_rotation_err = "Ensure AWS Secrets Manager automatic rotation is enabled." {
    aws_issue["secret_manager_automatic_rotation"]
}

secret_manager_automatic_rotation_metadata := {
    "Policy Code": "PR-AWS-TRF-SM-003",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure AWS Secrets Manager automatic rotation is enabled.",
    "Policy Description": "Rotation is the process of periodically updating a secret. When you rotate a secret, you update the credentials in both the secret and the database or service. This control checks if automatic rotation for secrets is enabled in the secrets manager configuration.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/secretsmanager_secret_rotation"
}


#
# PR-AWS-TRF-SM-004
#

default secret_manager_rotation_period = null

aws_issue["secret_manager_rotation_period"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_secretsmanager_secret_rotation"
    rotation_rule := resource.properties.rotation_rules[_]
    not rotation_rule.automatically_after_days
}

aws_issue["secret_manager_rotation_period"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_secretsmanager_secret_rotation"
    rotation_rule := resource.properties.rotation_rules[_]
    to_number(rotation_rule.automatically_after_days) > 30
}

secret_manager_rotation_period {
    lower(input.resources[i].type) == "aws_secretsmanager_secret_rotation"
    not aws_issue["secret_manager_rotation_period"]
}

secret_manager_rotation_period = false {
    aws_issue["secret_manager_rotation_period"]
}

secret_manager_rotation_period_err = "Ensure AWS secret rotation period is per the GS standard (Ex: 30 days)." {
    aws_issue["secret_manager_rotation_period"]
}

secret_manager_rotation_period_metadata := {
    "Policy Code": "PR-AWS-TRF-SM-004",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure AWS secret rotation period is per the GS standard (Ex: 30 days).",
    "Policy Description": "It checks if the rotation policy follow GS standards. Secret rotation period should be less than 30 days.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/secretsmanager_secret_rotation#automatically_after_days"
}


#
# PR-AWS-TRF-AS-002
#

default as_elb_health_check = null

aws_attribute_absence["as_elb_health_check"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_autoscaling_group"
    count(resource.properties.load_balancers) != 0
    not resource.properties.health_check_type
}

source_path[{"as_elb_health_check": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_autoscaling_group"
    count(resource.properties.load_balancers) != 0
    not resource.properties.health_check_type
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "health_check_type"]
        ],
    }
}

aws_issue["as_elb_health_check"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_autoscaling_group"
    count(resource.properties.load_balancers) != 0
    lower(resource.properties.health_check_type) != "elb"
}

source_path[{"as_elb_health_check": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_autoscaling_group"
    count(resource.properties.load_balancers) != 0
    lower(resource.properties.health_check_type) != "elb"
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "health_check_type"]
        ],
    }
}

aws_attribute_absence["as_elb_health_check"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_autoscaling_group"
    count(resource.properties.target_group_arns) != 0
    not resource.properties.health_check_type
}

source_path[{"as_elb_health_check": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_autoscaling_group"
    count(resource.properties.target_group_arns) != 0
    not resource.properties.health_check_type
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "health_check_type"]
        ],
    }
}

aws_issue["as_elb_health_check"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_autoscaling_group"
    count(resource.properties.target_group_arns) != 0
    lower(resource.properties.health_check_type) != "elb"
}

source_path[{"as_elb_health_check": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_autoscaling_group"
    count(resource.properties.target_group_arns) != 0
    lower(resource.properties.health_check_type) != "elb"
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "health_check_type"]
        ],
    }
}

as_elb_health_check {
    lower(input.resources[i].type) == "aws_autoscaling_group"
    not aws_issue["as_elb_health_check"]
    not aws_attribute_absence["as_elb_health_check"]
}

as_elb_health_check = false {
    aws_issue["as_elb_health_check"]
}

as_elb_health_check = false {
    aws_attribute_absence["as_elb_health_check"]
}

as_elb_health_check_err = "Ensure auto scaling groups associated with a load balancer use elastic load balancing health checks" {
    aws_issue["as_elb_health_check"]
} else = "Ensure auto scaling groups associated with a load balancer use elastic load balancing health checks" {
    aws_attribute_absence["as_elb_health_check"]
}

as_elb_health_check_metadata := {
    "Policy Code": "PR-AWS-TRF-AS-002",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure auto scaling groups associated with a load balancer use elastic load balancing health checks",
    "Policy Description": "If you configure an Auto Scaling group to use load balancer (ELB) health checks, it considers the instance unhealthy if it fails either the EC2 status checks or the load balancer health checks",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/autoscaling_group"
}


#
# PR-AWS-TRF-AS-003
#

default as_http_token = null

aws_issue["as_http_token"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_launch_configuration"
    metadata_option := resource.properties.metadata_options[_]
    lower(metadata_option.http_tokens) != "required"
}

aws_attribute_absence["as_http_token"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_launch_configuration"
    metadata_option := resource.properties.metadata_options[_]
    not metadata_option.http_tokens
}

as_http_token {
    lower(input.resources[i].type) == "aws_launch_configuration"
    not aws_issue["as_http_token"]
    not aws_attribute_absence["as_http_token"]
}

as_http_token = false {
    aws_issue["as_http_token"]
}

as_http_token = false {
    aws_attribute_absence["as_http_token"]
}

as_http_token_err = "Ensure EC2 Auto Scaling Group does not launch IMDSv1" {
    aws_issue["as_http_token"]
} else = "Ensure EC2 Auto Scaling Group does not launch IMDSv1" {
    aws_attribute_absence["as_http_token"]
}

as_http_token_metadata := {
    "Policy Code": "PR-AWS-TRF-AS-003",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure EC2 Auto Scaling Group does not launch IMDSv1",
    "Policy Description": "This control checks if EC2 instances use IMDSv1 instead of IMDSv2, this also applies to instances created in the ASG.IMDSv1 is vulnerable to Server Side Request Forgery (SSRF) vulnerabilities in web applications running on EC2, open Website Application Firewalls, open reverse proxies, and open layer 3 firewalls and NATs. IMDSv2 uses session-oriented requests every request is now protected by session authentication.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/launch_configuration"
}


#
# PR-AWS-TRF-LG-001
#

default log_group_encryption = null

aws_issue["log_group_encryption"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudwatch_log_group"
    not resource.properties.kms_key_id
}

source_path[{"log_group_encryption": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudwatch_log_group"
    not resource.properties.kms_key_id
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "kms_key_id"]
        ],
    }
}

aws_issue["log_group_encryption"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudwatch_log_group"
    count(resource.properties.kms_key_id) == 0
}

source_path[{"log_group_encryption": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudwatch_log_group"
    count(resource.properties.kms_key_id) == 0
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "kms_key_id"]
        ],
    }
}

aws_issue["log_group_encryption"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudwatch_log_group"
    resource.properties.kms_key_id == null
}

source_path[{"log_group_encryption": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudwatch_log_group"
    resource.properties.kms_key_id == null
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "kms_key_id"]
        ],
    }
}

log_group_encryption {
    lower(input.resources[i].type) == "aws_cloudwatch_log_group"
    not aws_issue["log_group_encryption"]
}

log_group_encryption = false {
    aws_issue["log_group_encryption"]
}

log_group_encryption_err = "Ensure CloudWatch log groups are encrypted with KMS CMKs" {
    aws_issue["log_group_encryption"]
}

log_group_encryption_metadata := {
    "Policy Code": "PR-AWS-TRF-LG-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure CloudWatch log groups are encrypted with KMS CMKs",
    "Policy Description": "CloudWatch log groups are encrypted by default. However, utilizing KMS CMKs gives you more control over key rotation and provides auditing visibility into key usage.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_group"
}


#
# PR-AWS-TRF-LG-002
#

default log_group_retention = null

aws_issue["log_group_retention"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudwatch_log_group"
    not resource.properties.retention_in_days
}

source_path[{"log_group_retention": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudwatch_log_group"
    not resource.properties.retention_in_days
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "retention_in_days"]
        ],
    }
}

log_group_retention {
    lower(input.resources[i].type) == "aws_cloudwatch_log_group"
    not aws_issue["log_group_retention"]
}

log_group_retention = false {
    aws_issue["log_group_retention"]
}

log_group_retention_err = "Ensure CloudWatch log groups has retention days defined" {
    aws_issue["log_group_retention"]
}

log_group_retention_metadata := {
    "Policy Code": "PR-AWS-TRF-LG-002",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure CloudWatch log groups has retention days defined",
    "Policy Description": "Ensure that your web-tier CloudWatch log group has the retention period feature configured in order to establish how long log events are kept in AWS CloudWatch logs",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_group"
}


#
# PR-AWS-TRF-WS-001
#

default workspace_volume_encrypt = null

aws_issue["workspace_volume_encrypt"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_workspaces_workspace"
    not resource.properties.user_volume_encryption_enabled
}

source_path[{"workspace_volume_encrypt": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_workspaces_workspace"
    not resource.properties.user_volume_encryption_enabled
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "user_volume_encryption_enabled"]
        ],
    }
}

aws_issue["workspace_volume_encrypt"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_workspaces_workspace"
    lower(resource.properties.user_volume_encryption_enabled) == "false"
}

source_path[{"workspace_volume_encrypt": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_workspaces_workspace"
    lower(resource.properties.user_volume_encryption_enabled) == "false"
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "user_volume_encryption_enabled"]
        ],
    }
}

workspace_volume_encrypt {
    lower(input.resources[i].type) == "aws_workspaces_workspace"
    not aws_issue["workspace_volume_encrypt"]
}

workspace_volume_encrypt = false {
    aws_issue["workspace_volume_encrypt"]
}

workspace_volume_encrypt_err = "Ensure that Workspace user volumes is encrypted" {
    aws_issue["workspace_volume_encrypt"]
}

workspace_volume_encrypt_metadata := {
    "Policy Code": "PR-AWS-TRF-WS-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that Workspace user volumes is encrypted",
    "Policy Description": "Ensure that your Amazon WorkSpaces storage volumes are encrypted in order to meet security and compliance requirements. Your data is transparently encrypted while being written and transparently decrypted while being read from your storage volumes, therefore the encryption process does not require any additional action from you",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/workspaces_workspace"
}


#
# PR-AWS-TRF-WS-002
#

default workspace_root_volume_encrypt = null

aws_issue["workspace_root_volume_encrypt"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_workspaces_workspace"
    not resource.properties.root_volume_encryption_enabled
}

aws_issue["workspace_root_volume_encrypt"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_workspaces_workspace"
    lower(resource.properties.root_volume_encryption_enabled) == "false"
}

workspace_root_volume_encrypt {
    lower(input.resources[i].type) == "aws_workspaces_workspace"
    not aws_issue["workspace_root_volume_encrypt"]
}

workspace_root_volume_encrypt = false {
    aws_issue["workspace_root_volume_encrypt"]
}

workspace_root_volume_encrypt_err = "Ensure that Workspace root volumes is encrypted." {
    aws_issue["workspace_root_volume_encrypt"]
}

workspace_root_volume_encrypt_metadata := {
    "Policy Code": "PR-AWS-TRF-WS-002",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that Workspace root volumes is encrypted.",
    "Policy Description": "It checks if encryption is enabled for workspace root volumes.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/workspaces_workspace"
}


#
# PR-AWS-TRF-WS-003
#

default workspace_directory_type = null

aws_issue["workspace_directory_type"] {
    resource_1 := input.resources[i]
    lower(resource_1.type) == "aws_directory_service_directory"
    resource_1.properties.type == "SimpleAD"
    directoryid := resource_1.properties.name
    resource_2 := input.resources[j]
    lower(resource_2.type) == "aws_workspaces_workspace"
    resource_2.properties.directory_id == directoryid
}

aws_issue["workspace_directory_type"] {
    resource_1 := input.resources[i]
    lower(resource_1.type) == "aws_directory_service_directory"
    resource_1.properties.type == "SimpleAD"
    directoryid := resource_1.name
    resource_2 := input.resources[j]
    lower(resource_2.type) == "aws_workspaces_workspace"
    resource_2.properties.directory_id == directoryid
}

aws_issue["workspace_directory_type"] {
    resource_1 := input.resources[i]
    lower(resource_1.type) == "aws_directory_service_directory"
    not resource_1.properties.type
    directoryid := resource_1.properties.name
    resource_2 := input.resources[j]
    lower(resource_2.type) == "aws_workspaces_workspace"
    resource_2.properties.directory_id == directoryid
}

aws_issue["workspace_directory_type"] {
    resource_1 := input.resources[i]
    lower(resource_1.type) == "aws_directory_service_directory"
    not resource_1.properties.type
    directoryid := resource_1.name
    resource_2 := input.resources[j]
    lower(resource_2.type) == "aws_workspaces_workspace"
    resource_2.properties.directory_id == directoryid
}

workspace_directory_type {
    lower(input.resources[i].type) == "aws_workspaces_workspace"
    not aws_issue["workspace_directory_type"]
}

workspace_directory_type = false {
    aws_issue["workspace_directory_type"]
}

workspace_directory_type_err = "Ensure AWS WorkSpaces do not use directory type Simple AD." {
    aws_issue["workspace_directory_type"]
}

workspace_directory_type_metadata := {
    "Policy Code": "PR-AWS-TRF-WS-003",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure AWS WorkSpaces do not use directory type Simple AD.",
    "Policy Description": "It checks if Simple AD is used for workspace users. MS Active Directory is approved by GS to be used.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/workspaces_workspace"
}


#
# PR-AWS-TRF-CFR-001
#

default cf_sns = null

aws_issue["cf_sns"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudformation_stack"
    not resource.properties.notification_arns
}

source_path[{"cf_sns": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudformation_stack"
    not resource.properties.notification_arns

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "notification_arns"]
        ],
    }
}

aws_issue["cf_sns"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudformation_stack"
    count(resource.properties.notification_arns) == 0
}

source_path[{"cf_sns": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudformation_stack"
    count(resource.properties.notification_arns) == 0

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "notification_arns"]
        ],
    }
}

cf_sns {
    lower(input.resources[i].type) == "aws_cloudformation_stack"
    not aws_issue["cf_sns"]
}

cf_sns = false {
    aws_issue["cf_sns"]
}

cf_sns_err = "AWS CloudFormation stack configured without SNS topic" {
    aws_issue["cf_sns"]
}

cf_sns_metadata := {
    "Policy Code": "PR-AWS-TRF-CFR-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS CloudFormation stack configured without SNS topic",
    "Policy Description": "This policy identifies CloudFormation stacks which are configured without SNS topic. It is recommended to configure Simple Notification Service (SNS) topic to be notified of CloudFormation stack status and changes.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-stack.html"
}

#
# PR-AWS-TRF-CFR-002
#

default cloudFormation_template_configured_with_stack_policy = null

aws_issue["cloudFormation_template_configured_with_stack_policy"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudformation_stack"
    not resource.properties.policy_body
}

aws_issue["cloudFormation_template_configured_with_stack_policy"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudformation_stack"
    not resource.properties.policy_url
}

cloudFormation_template_configured_with_stack_policy {
    lower(input.resources[i].type) == "aws_cloudformation_stack"
    not aws_issue["cloudFormation_template_configured_with_stack_policy"]
}

cloudFormation_template_configured_with_stack_policy = false {
    aws_issue["cloudFormation_template_configured_with_stack_policy"]
}

cloudFormation_template_configured_with_stack_policy_err = "Ensure CloudFormation template is configured with stack policy." {
    aws_issue["cloudFormation_template_configured_with_stack_policy"]
}

cloudFormation_template_configured_with_stack_policy_metadata := {
    "Policy Code": "PR-AWS-TRF-CFR-002",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure CloudFormation template is configured with stack policy.",
    "Policy Description": "In AWS IAM policy governs how much access/permission the stack has and if no policy is provided it assumes the permissions of the user running it.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudformation_stack"
}

#
# PR-AWS-TRF-CFR-003
#

default cloudFormation_rollback_is_disabled = null

aws_issue["cloudFormation_rollback_is_disabled"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudformation_stack"
    resource.properties.disable_rollback == available_false_choices[_]
}

aws_issue["cloudFormation_rollback_is_disabled"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudformation_stack"
    not resource.properties.disable_rollback
}

cloudFormation_rollback_is_disabled {
    lower(input.resources[i].type) == "aws_cloudformation_stack"
    not aws_issue["cloudFormation_rollback_is_disabled"]
}

cloudFormation_rollback_is_disabled = false {
    aws_issue["cloudFormation_rollback_is_disabled"]
}

cloudFormation_rollback_is_disabled_err = "Ensure Cloudformation rollback is disabled." {
    aws_issue["cloudFormation_rollback_is_disabled"]
}

cloudFormation_rollback_is_disabled_metadata := {
    "Policy Code": "PR-AWS-TRF-CFR-003",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure Cloudformation rollback is disabled.",
    "Policy Description": "It checks the stack rollback setting, in case of a failure do not rollback the entire stack. We can use change sets run the stack again, after fixing the template. Resources which are already provisioned won't be re-created.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudformation_stack"
}

#
# PR-AWS-TRF-CFR-004
#

default role_arn_exist = null

aws_issue["role_arn_exist"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudformation_stack"
    not resource.properties.iam_role_arn
}

role_arn_exist {
    lower(input.resources[i].type) == "aws_cloudformation_stack"
    not aws_issue["role_arn_exist"]
}

role_arn_exist = false {
    aws_issue["role_arn_exist"]
}

role_arn_exist_err = "Ensure an IAM policy is defined with the stack." {
    aws_issue["role_arn_exist"]
}

role_arn_exist_metadata := {
    "Policy Code": "PR-AWS-TRF-CFR-004",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure an IAM policy is defined with the stack.",
    "Policy Description": "Stack policy protects resources from accidental updates, the policy included resources which shouldn't be updated during the template provisioning process.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudformation_stack"
}

#
# PR-AWS-TRF-CFR-005
#

default stack_with_not_all_capabilities = null

aws_issue["stack_with_not_all_capabilities"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudformation_stack"
    contains(resource.properties.capabilities[_], "*")
}

stack_with_not_all_capabilities {
    lower(input.resources[i].type) == "aws_cloudformation_stack"
    not aws_issue["stack_with_not_all_capabilities"]
}

stack_with_not_all_capabilities = false {
    aws_issue["stack_with_not_all_capabilities"]
}

stack_with_not_all_capabilities_err = "Ensure capabilities in stacks do not have * in it." {
    aws_issue["stack_with_not_all_capabilities"]
}

stack_with_not_all_capabilities_metadata := {
    "Policy Code": "PR-AWS-TRF-CFR-005",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure capabilities in stacks do not have * in it.",
    "Policy Description": "A CloudFormation stack needs certain capability, It is recommended to configure the stack with capabilities not all capabilities (*) should be configured. This will give the stack unlimited access.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudformation_stack"
}

#
# PR-AWS-TRF-CFG-001
#

default config_all_resource = null

aws_issue["config_all_resource"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_config_configuration_recorder"
    not resource.properties.recording_group
}

source_path[{"config_all_resource": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_config_configuration_recorder"
    not resource.properties.recording_group

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "recording_group"]
        ],
    }
}

aws_issue["config_all_resource"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_config_configuration_recorder"
    recording_group := resource.properties.recording_group[j]
    lower(recording_group.all_supported) == "false"
}

source_path[{"config_all_resource": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_config_configuration_recorder"
    recording_group := resource.properties.recording_group[j]
    lower(recording_group.all_supported) == "false"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "recording_group", j, "all_supported"]
        ],
    }
}

aws_issue["config_all_resource"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_config_configuration_recorder"
    recording_group := resource.properties.recording_group[j]
    lower(recording_group.include_global_resource_types) == "false"
}

source_path[{"config_all_resource": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_config_configuration_recorder"
    recording_group := resource.properties.recording_group[j]
    lower(recording_group.include_global_resource_types) == "false"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "recording_group", j, "include_global_resource_types"]
        ],
    }
}

aws_bool_issue["config_all_resource"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_config_configuration_recorder"
    recording_group := resource.properties.recording_group[j]
    not recording_group.all_supported
}

source_path[{"config_all_resource": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_config_configuration_recorder"
    recording_group := resource.properties.recording_group[j]
    not recording_group.all_supported

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "recording_group", j, "all_supported"]
        ],
    }
}

aws_bool_issue["config_all_resource"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_config_configuration_recorder"
    recording_group := resource.properties.recording_group[j]
    not recording_group.include_global_resource_types
}

source_path[{"config_all_resource": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_config_configuration_recorder"
    recording_group := resource.properties.recording_group[j]
    not recording_group.include_global_resource_types

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "recording_group", j, "include_global_resource_types"]
        ],
    }
}

config_all_resource {
    lower(input.resources[i].type) == "aws_config_configuration_recorder"
    not aws_issue["config_all_resource"]
    not aws_bool_issue["config_all_resource"]
}

config_all_resource = false {
    aws_issue["config_all_resource"]
}

config_all_resource = false {
    aws_bool_issue["config_all_resource"]
}

config_all_resource_err = "AWS Config must record all possible resources" {
    aws_issue["config_all_resource"]
} else = "AWS Config must record all possible resources" {
    aws_bool_issue["config_all_resource"]
}

config_all_resource_metadata := {
    "Policy Code": "PR-AWS-TRF-CFG-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Config must record all possible resources",
    "Policy Description": "This policy identifies resources for which AWS Config recording is enabled but recording for all possible resources are disabled. AWS Config provides an inventory of your AWS resources and a history of configuration changes to these resources. You can use AWS Config to define rules that evaluate these configurations for compliance. Hence, it is important to enable this feature.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-config-configurationrecorder.html"
}


#
# PR-AWS-TRF-CFG-002
#

default aws_config_configuration_aggregator = null

aws_issue["aws_config_configuration_aggregator"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_config_configuration_aggregator"
    organization_aggregation_source := resource.properties.organization_aggregation_source[j]
    not organization_aggregation_source.all_regions
}

source_path[{"aws_config_configuration_aggregator": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_config_configuration_aggregator"
    organization_aggregation_source := resource.properties.organization_aggregation_source[j]
    not organization_aggregation_source.all_regions
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "organization_aggregation_source", j, "all_regions"]
        ],
    }
}

aws_issue["aws_config_configuration_aggregator"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_config_configuration_aggregator"
    organization_aggregation_source := resource.properties.organization_aggregation_source[j]
    lower(organization_aggregation_source.all_regions) != "true"
}

source_path[{"aws_config_configuration_aggregator": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_config_configuration_aggregator"
    organization_aggregation_source := resource.properties.organization_aggregation_source[j]
    lower(organization_aggregation_source.all_regions) != "true"
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "organization_aggregation_source", j, "all_regions"]
        ],
    }
}

aws_config_configuration_aggregator {
    lower(input.resources[i].type) == "aws_config_configuration_aggregator"
    not aws_issue["aws_config_configuration_aggregator"]
}

aws_config_configuration_aggregator = false {
    aws_issue["aws_config_configuration_aggregator"]
}

aws_config_configuration_aggregator_err = "Ensure AWS config is enabled in all regions" {
    aws_issue["aws_config_configuration_aggregator"]
}

aws_config_configuration_aggregator_metadata := {
    "Policy Code": "PR-AWS-TRF-CFG-002",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure AWS config is enabled in all regions",
    "Policy Description": "AWS Config is a web service that performs the configuration management of supported AWS resources within your account and delivers log files to you.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/config_configuration_aggregator"
}

#
# PR-AWS-TRF-CFG-004
#

default config_includes_global_resources = null

aws_issue["config_includes_global_resources"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_config_configuration_recorder"
    recording_group := resource.properties.recording_group[j]
    recording_group.include_global_resource_types == available_false_choices[_]
}

aws_issue["config_includes_global_resources"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_config_configuration_recorder"
    recording_group := resource.properties.recording_group[j]
    not recording_group.include_global_resource_types
}

config_includes_global_resources {
    lower(input.resources[i].type) == "aws_config_configuration_recorder"
    not aws_issue["config_includes_global_resources"]
}

config_includes_global_resources = false {
    aws_issue["config_includes_global_resources"]
}

config_includes_global_resources_err = "Ensure AWS Config includes global resources types (IAM)." {
    aws_issue["config_includes_global_resources"]
}

config_includes_global_resources_metadata := {
    "Policy Code": "PR-AWS-TRF-CFG-004",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure AWS Config includes global resources types (IAM).",
    "Policy Description": "It checks that global resource types are included in AWS Config.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/config_configuration_recorder#include_global_resource_types"
}


#
# PR-AWS-TRF-KNS-001
#
default kinesis_encryption = null

aws_issue["kinesis_encryption"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_kinesis_stream"
    not resource.properties.encryption_type
}

source_path[{"kinesis_encryption": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_kinesis_stream"
    not resource.properties.encryption_type

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "encryption_type"]
        ],
    }
}

aws_issue["kinesis_encryption"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_kinesis_stream"
    resource.properties.encryption_type == null
}

source_path[{"kinesis_encryption": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_kinesis_stream"
    resource.properties.encryption_type == null

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "encryption_type"]
        ],
    }
}

aws_issue["kinesis_encryption"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_kinesis_stream"
    count(resource.properties.encryption_type) == 0
}

source_path[{"kinesis_encryption": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_kinesis_stream"
    count(resource.properties.encryption_type) == 0

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "encryption_type"]
        ],
    }
}

kinesis_encryption {
    lower(input.resources[i].type) == "aws_kinesis_stream"
    not aws_issue["kinesis_encryption"]
}

kinesis_encryption = false {
    aws_issue["kinesis_encryption"]
}

kinesis_encryption_err = "AWS Kinesis streams are not encrypted using Server Side Encryption" {
    aws_issue["kinesis_encryption"]
}

kinesis_encryption_metadata := {
    "Policy Code": "PR-AWS-TRF-KNS-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Kinesis streams are not encrypted using Server Side Encryption",
    "Policy Description": "This Policy identifies the AWS Kinesis streams which are not encrypted using Server Side Encryption. Server Side Encryption is used to encrypt your sensitive data before it is written to the Kinesis stream storage layer and decrypted after it is retrieved from storage.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-kinesis-stream.html#aws-resource-kinesis-stream--examples"
}

#
# PR-AWS-TRF-KNS-002
#

default kinesis_encryption_kms = null

aws_issue["kinesis_encryption_kms"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_kinesis_stream"
    not resource.properties.encryption_type
}

source_path[{"kinesis_encryption_kms": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_kinesis_stream"
    not resource.properties.encryption_type

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "encryption_type"]
        ],
    }
}

aws_issue["kinesis_encryption_kms"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_kinesis_stream"
    resource.properties.encryption_type == null
}

source_path[{"kinesis_encryption_kms": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_kinesis_stream"
    resource.properties.encryption_type == null

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "encryption_type"]
        ],
    }
}

aws_issue["kinesis_encryption_kms"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_kinesis_stream"
    lower(resource.properties.encryption_type) != "kms"
}

source_path[{"kinesis_encryption_kms": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_kinesis_stream"
    lower(resource.properties.encryption_type) != "kms"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "encryption_type"]
        ],
    }
}

kinesis_encryption_kms {
    lower(input.resources[i].type) == "aws_kinesis_stream"
    not aws_issue["kinesis_encryption_kms"]
}

kinesis_encryption_kms = false {
    aws_issue["kinesis_encryption_kms"]
}

kinesis_encryption_kms_err = "AWS Kinesis streams encryption using default KMS keys instead of Customer's Managed Master Keys" {
    aws_issue["kinesis_encryption_kms"]
}

kinesis_encryption_kms_metadata := {
    "Policy Code": "PR-AWS-TRF-KNS-002",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Kinesis streams encryption using default KMS keys instead of Customer's Managed Master Keys",
    "Policy Description": "This policy identifies the AWS Kinesis streams which are encrypted with default KMS keys and not with Master Keys managed by Customer. It is a best practice to use customer managed Master Keys to encrypt your Amazon Kinesis streams data. It gives you full control over the encrypted data.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-kinesis-stream.html#aws-resource-kinesis-stream--examples"
}

#
# PR-AWS-TRF-MQ-001
#
default mq_publicly_accessible = null

aws_bool_issue["mq_publicly_accessible"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_mq_broker"
    resource.properties.publicly_accessible == true
}

source_path[{"mq_publicly_accessible": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_mq_broker"
    resource.properties.publicly_accessible == true

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "publicly_accessible"]
        ],
    }
}

aws_issue["mq_publicly_accessible"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_mq_broker"
    lower(resource.properties.publicly_accessible) == "true"
}

source_path[{"mq_publicly_accessible": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_mq_broker"
    lower(resource.properties.publicly_accessible) == "true"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "publicly_accessible"]
        ],
    }
}

mq_publicly_accessible {
    lower(input.resources[i].type) == "aws_mq_broker"
    not aws_issue["mq_publicly_accessible"]
    not aws_bool_issue["mq_publicly_accessible"]
}

mq_publicly_accessible = false {
    aws_issue["mq_publicly_accessible"]
}

mq_publicly_accessible = false {
    aws_bool_issue["mq_publicly_accessible"]
}

mq_publicly_accessible_err = "AWS MQ is publicly accessible" {
    aws_issue["mq_publicly_accessible"]
} else = "AWS MQ is publicly accessible" {
    aws_bool_issue["mq_publicly_accessible"]
}


mq_publicly_accessible_metadata := {
    "Policy Code": "PR-AWS-TRF-MQ-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS MQ is publicly accessible",
    "Policy Description": "This policy identifies the AWS MQ brokers which are publicly accessible. It is advisable to use MQ brokers privately only from within your AWS Virtual Private Cloud (VPC). Ensure that the AWS MQ brokers provisioned in your AWS account are not publicly accessible from the Internet to avoid sensitive data exposure and minimize security risks.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-broker.html#cfn-amazonmq-broker-publiclyaccessible"
}

#
# PR-AWS-TRF-MQ-002
#
default mq_logging_enable = null

aws_issue["mq_logging_enable"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_mq_broker"
    not resource.properties.logs
}

source_path[{"mq_logging_enable": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_mq_broker"
    not resource.properties.logs
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "logs"]
        ],
    }
}

aws_issue["mq_logging_enable"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_mq_broker"
    count(resource.properties.logs) == 0
}

source_path[{"mq_logging_enable": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_mq_broker"
    count(resource.properties.logs) == 0
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "logs"]
        ],
    }
}

aws_issue["mq_logging_enable"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_mq_broker"
    logs := resource.properties.logs[j]
    not logs.general
}

source_path[{"mq_logging_enable": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_mq_broker"
    logs := resource.properties.logs[j]
    not logs.general
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "logs", j, "general"]
        ],
    }
}

aws_issue["mq_logging_enable"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_mq_broker"
    logs := resource.properties.logs[j]
    lower(logs.general) == "false"
}

source_path[{"mq_logging_enable": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_mq_broker"
    logs := resource.properties.logs[j]
    lower(logs.general) == "false"
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "logs", j, "general"]
        ],
    }
}

mq_logging_enable {
    lower(input.resources[i].type) == "aws_mq_broker"
    not aws_issue["mq_logging_enable"]
}

mq_logging_enable = false {
    aws_issue["mq_logging_enable"]
}


mq_logging_enable_err = "Ensure Amazon MQ Broker logging is enabled" {
    aws_issue["mq_logging_enable"]
}


mq_logging_enable_metadata := {
    "Policy Code": "PR-AWS-TRF-MQ-002",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure Amazon MQ Broker logging is enabled",
    "Policy Description": "Amazon MQ is integrated with CloudTrail and provides a record of the Amazon MQ calls made by a user, role, or AWS service. It supports logging both the request parameters and the responses for APIs as events in CloudTrail",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/mq_broker"
}


#
# PR-AWS-TRF-MQ-003
#

default mq_activemq_approved_engine_version = null

aws_issue["mq_activemq_approved_engine_version"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_mq_broker"
    lower(resource.properties.engine_type) == "activemq"
    not startswith(resource.properties.engine_version, "5.16")
}

mq_activemq_approved_engine_version {
    lower(input.resources[i].type) == "aws_mq_broker"
    not aws_issue["mq_activemq_approved_engine_version"]
}

mq_activemq_approved_engine_version = false {
    aws_issue["mq_activemq_approved_engine_version"]
}

mq_activemq_approved_engine_version_err = "Ensure ActiveMQ engine version is approved by GS." {
    aws_issue["mq_activemq_approved_engine_version"]
}

mq_activemq_approved_engine_version_metadata := {
    "Policy Code": "PR-AWS-TRF-MQ-003",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure ActiveMQ engine version is approved by GS.",
    "Policy Description": "It is used to check only firm approved version of ActiveMQ is being used.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/mq_broker"
}


#
# PR-AWS-TRF-MQ-004
#

default mq_rabbitmq_approved_engine_version = null

aws_issue["mq_rabbitmq_approved_engine_version"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_mq_broker"
    lower(resource.properties.engine_type) == "rabbitmq"
    not startswith(resource.properties.engine_version, "3.8")
}

mq_rabbitmq_approved_engine_version {
    lower(input.resources[i].type) == "aws_mq_broker"
    not aws_issue["mq_rabbitmq_approved_engine_version"]
}

mq_rabbitmq_approved_engine_version = false {
    aws_issue["mq_rabbitmq_approved_engine_version"]
}

mq_rabbitmq_approved_engine_version_err = "Ensure RabbitMQ engine version is approved by GS." {
    aws_issue["mq_rabbitmq_approved_engine_version"]
}

mq_rabbitmq_approved_engine_version_metadata := {
    "Policy Code": "PR-AWS-TRF-MQ-004",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure RabbitMQ engine version is approved by GS.",
    "Policy Description": "It is used to check only firm approved version of RabbitMQ is being used.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/mq_broker"
}


#
# PR-AWS-TRF-MQ-005
#

default audit_logs_published_to_cloudWatch = null

aws_issue["audit_logs_published_to_cloudWatch"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_mq_broker"
    lower(resource.properties.engine_type) == "activemq"
    not resource.properties.logs
}

aws_issue["audit_logs_published_to_cloudWatch"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_mq_broker"
    lower(resource.properties.engine_type) == "activemq"
    log := resource.properties.logs[j]
    not log.audit
}

aws_issue["audit_logs_published_to_cloudWatch"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_mq_broker"
    lower(resource.properties.engine_type) == "activemq"
    log := resource.properties.logs[j]
    lower(log.audit) == "false"
}

audit_logs_published_to_cloudWatch {
    lower(input.resources[i].type) == "aws_mq_broker"
    not aws_issue["audit_logs_published_to_cloudWatch"]
}

audit_logs_published_to_cloudWatch = false {
    aws_issue["audit_logs_published_to_cloudWatch"]
}

audit_logs_published_to_cloudWatch_err = "Ensure General and Audit logs are published to CloudWatch." {
    aws_issue["audit_logs_published_to_cloudWatch"]
}

audit_logs_published_to_cloudWatch_metadata := {
    "Policy Code": "PR-AWS-TRF-MQ-005",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure General and Audit logs are published to CloudWatch.",
    "Policy Description": "It is used to check that Amazon MQ is configured to push logs to CloudWatch in order to enhance troubleshooting in case of issues. It does not apply to RabbitMQ brokers.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/mq_broker"
}


#
# PR-AWS-TRF-R53-001
#

default route_healthcheck_disable = null

aws_issue["route_healthcheck_disable"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_route53_record"
    alias := resource.properties.alias[j]
    lower(alias.evaluate_target_health) == "false"
}

source_path[{"route_healthcheck_disable": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_route53_record"
    alias := resource.properties.alias[j]
    lower(alias.evaluate_target_health) == "false"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "alias", j, "evaluate_target_health"]
        ],
    }
}

aws_bool_issue["route_healthcheck_disable"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_route53_record"
    alias := resource.properties.alias[j]
    not alias.evaluate_target_health
}

source_path[{"route_healthcheck_disable": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_route53_record"
    alias := resource.properties.alias[j]
    not alias.evaluate_target_health

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "alias", j, "evaluate_target_health"]
        ],
    }
}

route_healthcheck_disable {
    lower(input.resources[i].type) == "aws_route53_record"
    not aws_issue["route_healthcheck_disable"]
    not aws_bool_issue["route_healthcheck_disable"]
}

route_healthcheck_disable = false {
    aws_issue["route_healthcheck_disable"]
}

route_healthcheck_disable = false {
    aws_bool_issue["route_healthcheck_disable"]
}

route_healthcheck_disable_err = "Ensure Route53 DNS evaluateTargetHealth is enabled" {
    aws_issue["route_healthcheck_disable"]
} else = "Ensure Route53 DNS evaluateTargetHealth is enabled" {
    aws_bool_issue["route_healthcheck_disable"]
}

route_healthcheck_disable_metadata := {
    "Policy Code": "PR-AWS-TRF-R53-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure Route53 DNS evaluateTargetHealth is enabled",
    "Policy Description": "The EvaluateTargetHealth of Route53 is not enabled, an alias record can't inherits the health of the referenced AWS resource, such as an ELB load balancer or another record in the hosted zone.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html"
}

#
# PR-AWS-TRF-GLUE-001
#

default glue_catalog_encryption = null


aws_attribute_absence["glue_catalog_encryption"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_glue_data_catalog_encryption_settings"
    not resource.properties.data_catalog_encryption_settings
}

source_path[{"glue_catalog_encryption": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_glue_data_catalog_encryption_settings"
    not resource.properties.data_catalog_encryption_settings
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "data_catalog_encryption_settings"]
        ],
    }
}

aws_issue["glue_catalog_encryption"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_glue_data_catalog_encryption_settings"
    data_catalog_encryption_settings := resource.properties.data_catalog_encryption_settings[j]
    connection_password_encryption := data_catalog_encryption_settings.connection_password_encryption[k]
    not connection_password_encryption.return_connection_password_encrypted
}

source_path[{"glue_catalog_encryption": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_glue_data_catalog_encryption_settings"
    data_catalog_encryption_settings := resource.properties.data_catalog_encryption_settings[j]
    connection_password_encryption := data_catalog_encryption_settings.connection_password_encryption[k]
    not connection_password_encryption.return_connection_password_encrypted
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "data_catalog_encryption_settings", j, "connection_password_encryption", k, "return_connection_password_encrypted"]
        ],
    }
}

aws_issue["glue_catalog_encryption"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_glue_data_catalog_encryption_settings"
    data_catalog_encryption_settings := resource.properties.data_catalog_encryption_settings[j]
    connection_password_encryption := data_catalog_encryption_settings.connection_password_encryption[k]
    lower(connection_password_encryption.return_connection_password_encrypted) == "false"
}

source_path[{"glue_catalog_encryption": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_glue_data_catalog_encryption_settings"
    data_catalog_encryption_settings := resource.properties.data_catalog_encryption_settings[j]
    connection_password_encryption := data_catalog_encryption_settings.connection_password_encryption[k]
    lower(connection_password_encryption.return_connection_password_encrypted) == "false"
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "data_catalog_encryption_settings", j, "connection_password_encryption", k, "return_connection_password_encrypted"]
        ],
    }
}

aws_issue["glue_catalog_encryption"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_glue_data_catalog_encryption_settings"
    data_catalog_encryption_settings := resource.properties.data_catalog_encryption_settings[j]
    encryption_at_rest := data_catalog_encryption_settings.encryption_at_rest[k]
    not encryption_at_rest.catalog_encryption_mode
}

source_path[{"glue_catalog_encryption": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_glue_data_catalog_encryption_settings"
    data_catalog_encryption_settings := resource.properties.data_catalog_encryption_settings[j]
    encryption_at_rest := data_catalog_encryption_settings.encryption_at_rest[k]
    not encryption_at_rest.catalog_encryption_mode
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "data_catalog_encryption_settings", j, "encryption_at_rest", k, "catalog_encryption_mode"]
        ],
    }
}

aws_issue["glue_catalog_encryption"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_glue_data_catalog_encryption_settings"
    data_catalog_encryption_settings := resource.properties.data_catalog_encryption_settings[j]
    encryption_at_rest := data_catalog_encryption_settings.encryption_at_rest[k]
    lower(encryption_at_rest.catalog_encryption_mode) != "sse-kms"
}

source_path[{"glue_catalog_encryption": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_glue_data_catalog_encryption_settings"
    data_catalog_encryption_settings := resource.properties.data_catalog_encryption_settings[j]
    encryption_at_rest := data_catalog_encryption_settings.encryption_at_rest[k]
    lower(encryption_at_rest.catalog_encryption_mode) != "sse-kms"
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "data_catalog_encryption_settings", j, "encryption_at_rest", k, "catalog_encryption_mode"]
        ],
    }
}

glue_catalog_encryption {
    lower(input.resources[i].type) == "aws_glue_data_catalog_encryption_settings"
    not aws_issue["glue_catalog_encryption"]
    not aws_attribute_absence["glue_catalog_encryption"]
}

glue_catalog_encryption = false {
    aws_issue["glue_catalog_encryption"]
}

glue_catalog_encryption = false {
    aws_attribute_absence["glue_catalog_encryption"]
}

glue_catalog_encryption_err = "Ensure Glue Data Catalog encryption is enabled" {
    aws_issue["glue_catalog_encryption"]
} else = "Ensure Glue Data Catalog encryption is enabled" {
    aws_attribute_absence["glue_catalog_encryption"]
}

glue_catalog_encryption_metadata := {
    "Policy Code": "PR-AWS-TRF-GLUE-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure Glue Data Catalog encryption is enabled",
    "Policy Description": "Ensure that encryption at rest is enabled for your Amazon Glue Data Catalogs in order to meet regulatory requirements and prevent unauthorized users from getting access to sensitive data",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/glue_data_catalog_encryption_settings"
}

#
# PR-AWS-TRF-GLUE-002
#

default glue_security_config = null

aws_issue["glue_security_config"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_glue_security_configuration"
    not resource.properties.encryption_configuration
}

source_path[{"glue_security_config": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_glue_security_configuration"
    not resource.properties.encryption_configuration
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "encryption_configuration"]
        ],
    }
}

aws_issue["glue_security_config"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_glue_security_configuration"
    encryption_configuration := resource.properties.encryption_configuration[j]
    cloudwatch_encryption := encryption_configuration.cloudwatch_encryption[k]
    lower(cloudwatch_encryption.cloudwatch_encryption_mode) != "sse-kms"
}

source_path[{"glue_security_config": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_glue_security_configuration"
    encryption_configuration := resource.properties.encryption_configuration[j]
    cloudwatch_encryption := encryption_configuration.cloudwatch_encryption[k]
    lower(cloudwatch_encryption.cloudwatch_encryption_mode) != "sse-kms"
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "encryption_configuration", j, "cloudwatch_encryption", k, "cloudwatch_encryption_mode"]
        ],
    }
}

aws_issue["glue_security_config"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_glue_security_configuration"
    encryption_configuration := resource.properties.encryption_configuration[j]
    job_bookmarks_encryption := encryption_configuration.job_bookmarks_encryption[k]
    lower(job_bookmarks_encryption.job_bookmarks_encryption_mode) != "sse-kms"
}

source_path[{"glue_security_config": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_glue_security_configuration"
    encryption_configuration := resource.properties.encryption_configuration[j]
    job_bookmarks_encryption := encryption_configuration.job_bookmarks_encryption[k]
    lower(job_bookmarks_encryption.job_bookmarks_encryption_mode) != "sse-kms"
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "encryption_configuration", j, "job_bookmarks_encryption", k, "job_bookmarks_encryption_mode"]
        ],
    }
}

aws_issue["glue_security_config"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_glue_security_configuration"
    encryption_configuration := resource.properties.encryption_configuration[j]
    s3_encryption := encryption_configuration.s3_encryption[k]
    lower(s3_encryption.s3_encryption_mode) != "sse-kms"
}

source_path[{"glue_security_config": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_glue_security_configuration"
    encryption_configuration := resource.properties.encryption_configuration[j]
    s3_encryption := encryption_configuration.s3_encryption[k]
    lower(s3_encryption.s3_encryption_mode) != "sse-kms"
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "encryption_configuration", j, "s3_encryption", k, "s3_encryption_mode"]
        ],
    }
}

glue_security_config {
    lower(input.resources[i].type) == "aws_glue_security_configuration"
    not aws_issue["glue_security_config"]
}

glue_security_config = false {
    aws_issue["glue_security_config"]
}

glue_security_config_err = "Ensure AWS Glue security configuration encryption is enabled" {
    aws_issue["glue_security_config"]
}

glue_security_config_metadata := {
    "Policy Code": "PR-AWS-TRF-GLUE-002",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure AWS Glue security configuration encryption is enabled",
    "Policy Description": "Ensure AWS Glue security configuration encryption is enabled",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/glue_security_configuration"
}


#
# PR-AWS-TRF-GLUE-003
#

default glue_encrypt_data_at_rest = null

aws_issue["glue_encrypt_data_at_rest"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_glue_security_configuration"
    encryption_configuration := resource.properties.encryption_configuration[j]
    cloudwatch_encryption := encryption_configuration.cloudwatch_encryption[k]
    lower(cloudwatch_encryption.cloudwatch_encryption_mode) == "disabled"
}

aws_issue["glue_encrypt_data_at_rest"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_glue_security_configuration"
    encryption_configuration := resource.properties.encryption_configuration[j]
    cloudwatch_encryption := encryption_configuration.cloudwatch_encryption[k]
    not cloudwatch_encryption.cloudwatch_encryption_mode
}

aws_issue["glue_encrypt_data_at_rest"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_glue_security_configuration"
    encryption_configuration := resource.properties.encryption_configuration[j]
    job_bookmarks_encryption := encryption_configuration.job_bookmarks_encryption[k]
    lower(job_bookmarks_encryption.job_bookmarks_encryption_mode) == "disabled"
}

aws_issue["glue_encrypt_data_at_rest"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_glue_security_configuration"
    encryption_configuration := resource.properties.encryption_configuration[j]
    job_bookmarks_encryption := encryption_configuration.job_bookmarks_encryption[k]
    not job_bookmarks_encryption.job_bookmarks_encryption_mode
}

aws_issue["glue_encrypt_data_at_rest"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_glue_security_configuration"
    encryption_configuration := resource.properties.encryption_configuration[j]
    s3_encryption := encryption_configuration.s3_encryption[k]
    lower(s3_encryption.s3_encryption_mode) == "disabled"
}

aws_issue["glue_encrypt_data_at_rest"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_glue_security_configuration"
    encryption_configuration := resource.properties.encryption_configuration[j]
    s3_encryption := encryption_configuration.s3_encryption[k]
    not s3_encryption.s3_encryption_mode
}

glue_encrypt_data_at_rest {
    lower(input.resources[i].type) == "aws_glue_security_configuration"
    not aws_issue["glue_encrypt_data_at_rest"]
}

glue_encrypt_data_at_rest = false {
    aws_issue["glue_encrypt_data_at_rest"]
}

glue_encrypt_data_at_rest_err = "Ensure AWS Glue encrypt data at rest" {
    aws_issue["glue_encrypt_data_at_rest"]
}

glue_encrypt_data_at_rest_metadata := {
    "Policy Code": "PR-AWS-TRF-GLUE-003",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure AWS Glue encrypt data at rest",
    "Policy Description": "It is to check that AWS Glue encryption at rest is enabled.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/glue_security_configuration"
}


#
# PR-AWS-TRF-AS-001
#

default as_volume_encrypted = null

aws_issue["as_volume_encrypted"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_launch_configuration"
    count([c | resource.properties.ebs_block_device; c:=1]) == 0
}

source_path[{"as_volume_encrypted": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_launch_configuration"
    count([c | resource.properties.ebs_block_device; c:=1]) == 0

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "ebs_block_device"]
        ],
    }
}

aws_bool_issue["as_volume_encrypted"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_launch_configuration"
    ebs_block_device := resource.properties.ebs_block_device[j]
    not ebs_block_device.encrypted
}

source_path[{"as_volume_encrypted": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_launch_configuration"
    ebs_block_device := resource.properties.ebs_block_device[j]
    not ebs_block_device.encrypted

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "ebs_block_device", j, "encrypted"]
        ],
    }
}

aws_issue["as_volume_encrypted"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_launch_configuration"
    ebs_block_device := resource.properties.ebs_block_device[j]
    lower(ebs_block_device.encrypted) != "true"
}

source_path[{"as_volume_encrypted": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_launch_configuration"
    ebs_block_device := resource.properties.ebs_block_device[j]
    lower(ebs_block_device.encrypted) != "true"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "ebs_block_device", j, "encrypted"]
        ],
    }
}

as_volume_encrypted {
    lower(input.resources[i].type) == "aws_launch_configuration"
    not aws_issue["as_volume_encrypted"]
    not aws_bool_issue["as_volume_encrypted"]
}

as_volume_encrypted = false {
    aws_issue["as_volume_encrypted"]
}

as_volume_encrypted = false {
    aws_bool_issue["as_volume_encrypted"]
}

as_volume_encrypted_err = "Ensure EBS volumes have encrypted launch configurations" {
    aws_issue["as_volume_encrypted"]
} else = "Ensure EBS volumes have encrypted launch configurations" {
    aws_bool_issue["as_volume_encrypted"]
}

as_volume_encrypted_metadata := {
    "Policy Code": "PR-AWS-TRF-AS-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure EBS volumes have encrypted launch configurations",
    "Policy Description": "Amazon Elastic Block Store (EBS) volumes allow you to create encrypted launch configurations when creating EC2 instances and auto scaling. When the entire EBS volume is encrypted, data stored at rest on the volume, disk I/O, snapshots created from the volume, and data in-transit between EBS and EC2 are all encrypted.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-launchconfig-blockdev-template.html#cfn-as-launchconfig-blockdev-template-encrypted"
}

#
# PR-AWS-TRF-WAF-001
#

default waf_log4j_vulnerability = null

aws_issue["waf_log4j_vulnerability"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_wafv2_web_acl"
    rule := resource.properties.rule[_]
    statement := rule.statement[_]
    managed_rule_group_statement := statement.managed_rule_group_statement[_]
    lower(managed_rule_group_statement.name) == "awsmanagedrulesknownbadinputsruleset"
    excluded_rule := managed_rule_group_statement.excluded_rule[_]
    lower(excluded_rule.name) == "log4jrce"
}

aws_issue["waf_log4j_vulnerability"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_wafv2_web_acl"
    rule := resource.properties.rule[_]
    not has_property(rule.override_action, "none")
}

waf_log4j_vulnerability {
    lower(input.resources[i].type) == "aws_wafv2_web_acl"
    not aws_issue["waf_log4j_vulnerability"]
}

waf_log4j_vulnerability = false {
    aws_issue["waf_log4j_vulnerability"]
}

waf_log4j_vulnerability_err = "JMSAppender in Log4j 1.2 is vulnerable to deserialization of untrusted data when the attacker has write access to the Log4j configuration" {
    aws_issue["waf_log4j_vulnerability"]
}

waf_log4j_vulnerability_metadata := {
    "Policy Code": "PR-AWS-TRF-WAF-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "JMSAppender in Log4j 1.2 is vulnerable to deserialization of untrusted data when the attacker has write access to the Log4j configuration",
    "Policy Description": "Apache Log4j2 2.0-beta9 through 2.12.1 and 2.13.0 through 2.15.0 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-managedrulegroupstatement.html#cfn-wafv2-webacl-managedrulegroupstatement-name"
}



#
# PR-AWS-TRF-INS-001
#

default ins_package = null

aws_issue["ins_package"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_inspector_assessment_template"
    count([c | lower(resource.properties.rules_package_arns[_]) == lower(rules_packages[_]); c:=1]) == 0
}

aws_issue["ins_package"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_inspector_assessment_template"
    count(resource.properties.rules_package_arns) == 0
}

aws_issue["ins_package"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_inspector_assessment_template"
    not resource.properties.rules_package_arns
}

ins_package {
    lower(input.resources[i].type) == "aws_inspector_assessment_template"
    not aws_issue["ins_package"]
}

ins_package = false {
    aws_issue["ins_package"]
}

ins_package_err = "Enable AWS Inspector to detect Vulnerability" {
    aws_issue["ins_package"]
}

ins_package_metadata := {
    "Policy Code": "PR-AWS-TRF-INS-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Enable AWS Inspector to detect Vulnerability",
    "Policy Description": "Enable AWS Inspector to detect Vulnerability",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/inspector_assessment_template"
}

#
# PR-AWS-TRF-APS-001
#

default appsync_not_configured_with_firewall_v2 = null

aws_issue["appsync_not_configured_with_firewall_v2"] {
    lower(input.resources[i].type) =="aws_appsync_graphql_api"
    output := concat(".", [input.resources[i].type, input.resources[i].name, "arn"])
    count([c | 
        contains(lower(input.resources[j].properties.resource_arn), lower(output)); 
        lower(input.resources[j].type) == "aws_wafv2_web_acl_association";
        input.resources[j].properties.web_acl_arn;
        c:=1 
    ]) == 0
}

appsync_not_configured_with_firewall_v2 {
    lower(input.resources[i].type) == "aws_appsync_graphql_api"
    not aws_issue["appsync_not_configured_with_firewall_v2"]
}

appsync_not_configured_with_firewall_v2 = false {
    aws_issue["appsync_not_configured_with_firewall_v2"]
}

appsync_not_configured_with_firewall_v2_err = "Ensure AppSync is configured with AWS Web Application Firewall v2." {
    aws_issue["appsync_not_configured_with_firewall_v2"]
}

appsync_not_configured_with_firewall_v2_metadata := {
    "Policy Code": "PR-AWS-TRF-APS-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure AppSync is configured with AWS Web Application Firewall v2.",
    "Policy Description": "Enable the AWS WAF service on AppSync to protect against application layer attacks. To block malicious requests to your AppSync, define the block criteria in the WAF web access control list (web ACL).",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/appsync_graphql_api#associate-web-acl-v2"
}
