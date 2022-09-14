package rule

available_true_choices := ["true", true]
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


# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-apigateway-stage.html


#
# PR-AWS-CLD-SM-001
#

default secret_manager_kms = true

secret_manager_kms = false {
    # lower(resource.Type) == "aws::secretsmanager::secret"
    SecretList := input.SecretList[_]
    not SecretList.KmsKeyId
}

secret_manager_kms = false {
    # lower(resource.Type) == "aws::secretsmanager::secret"
    SecretList := input.SecretList[_]
    count(SecretList.KmsKeyId) == 0
}

secret_manager_kms_err = "Ensure that Secrets Manager secret is encrypted using KMS" {
    not secret_manager_kms
}

secret_manager_kms_metadata := {
    "Policy Code": "PR-AWS-CLD-SM-001",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure that Secrets Manager secret is encrypted using KMS",
    "Policy Description": "Ensure that your Amazon Secrets Manager secrets (i.e. database credentials, API keys, OAuth tokens, etc) are encrypted with Amazon KMS Customer Master Keys instead of default encryption keys that Secrets Manager service creates for you, in order to have a more control over secret data encryption and decryption process",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-secretsmanager-secret.html"
}

#
# PR-AWS-CLD-SM-003
# aws::secretsmanager::secret

default secret_manager_automatic_rotation = true

secret_manager_automatic_rotation = false {
    SecretList := input.SecretList[_]
    not SecretList.RotationEnabled
}

secret_manager_automatic_rotation = false {
    SecretList := input.SecretList[_]
    SecretList.RotationEnabled == available_false_choices[_]
}

secret_manager_automatic_rotation_err = "Ensure AWS Secrets Manager automatic rotation is enabled." {
    not secret_manager_automatic_rotation
}

secret_manager_automatic_rotation_metadata := {
    "Policy Code": "PR-AWS-CLD-SM-003",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS Secrets Manager automatic rotation is enabled.",
    "Policy Description": "Rotation is the process of periodically updating a secret. When you rotate a secret, you update the credentials in both the secret and the database or service. This control checks if automatic rotation for secrets is enabled in the secrets manager configuration.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/secretsmanager.html#SecretsManager.Client.list_secrets"
}

#
# PR-AWS-CLD-SM-004
# aws::secretsmanager::secret

default secret_manager_rotation_period = true

secret_manager_rotation_period = false {
    SecretList := input.SecretList[_]
    to_number(SecretList.RotationRules.AutomaticallyAfterDays) > 30
}

secret_manager_rotation_period = false {
    SecretList := input.SecretList[_]
    not SecretList.RotationRules.AutomaticallyAfterDays
}

secret_manager_rotation_period_err = "Ensure AWS secret rotation period is per the GS standard (Ex: 30 days)." {
    not secret_manager_rotation_period
}

secret_manager_rotation_period_metadata := {
    "Policy Code": "PR-AWS-CLD-SM-004",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS secret rotation period is per the GS standard (Ex: 30 days).",
    "Policy Description": "It checks if the rotation policy follow GS standards. Secret rotation period should be less than 30 days.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/secretsmanager.html#SecretsManager.Client.list_secrets"
}

#
# PR-AWS-CLD-LG-001
#

default log_group_encryption = true

log_group_encryption = false {
    # lower(resource.Type) == "aws::logs::loggroup"
    logGroups := input.logGroups[_]
    not logGroups.KmsKeyId
}

log_group_encryption = false {
    # lower(resource.Type) == "aws::logs::loggroup"
    logGroups := input.logGroups[_]
    count(logGroups.KmsKeyId) == 0
}

log_group_encryption = false {
    # lower(resource.Type) == "aws::logs::loggroup"
    logGroups := input.logGroups[_]
    logGroups.KmsKeyId == null
}

log_group_encryption_err = "Ensure CloudWatch log groups are encrypted with KMS CMKs" {
    not log_group_encryption
}

log_group_encryption_metadata := {
    "Policy Code": "PR-AWS-CLD-LG-001",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure CloudWatch log groups are encrypted with KMS CMKs",
    "Policy Description": "CloudWatch log groups are encrypted by default. However, utilizing KMS CMKs gives you more control over key rotation and provides auditing visibility into key usage.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-loggroup.html"
}

#
# PR-AWS-CLD-LG-002
#

default log_group_retention = true

log_group_retention = false {
    # lower(resource.Type) == "aws::logs::loggroup"
    logGroups := input.logGroups[_]
    not logGroups.RetentionInDays
}

log_group_retention_err = "Ensure CloudWatch log groups has retention days defined" {
    not log_group_retention
}

log_group_retention_metadata := {
    "Policy Code": "PR-AWS-CLD-LG-002",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure CloudWatch log groups has retention days defined",
    "Policy Description": "Ensure that your web-tier CloudWatch log group has the retention period feature configured in order to establish how long log events are kept in AWS CloudWatch Logs",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-loggroup.html"
}


#
# PR-AWS-CLD-WS-001
#

default workspace_volume_encrypt = true

workspace_volume_encrypt = false {
    # lower(resource.Type) == "aws::workspaces::workspace"
    Workspaces := input.Workspaces[_]
    not Workspaces.UserVolumeEncryptionEnabled
}

workspace_volume_encrypt_err = "Ensure that Workspace user volumes is encrypted" {
    not workspace_volume_encrypt
}

workspace_volume_encrypt_metadata := {
    "Policy Code": "PR-AWS-CLD-WS-001",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure that Workspace user volumes is encrypted",
    "Policy Description": "Ensure that your Amazon WorkSpaces storage volumes are encrypted in order to meet security and compliance requirements. Your data is transparently encrypted while being written and transparently decrypted while being read from your storage volumes, therefore the encryption process does not require any additional action from you",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-workspaces-workspace.html"
}


#
# PR-AWS-CLD-WS-002
# aws::workspaces::workspace

default workspace_root_volume_encrypt = true

workspace_root_volume_encrypt = false {
    Workspaces := input.Workspaces[_]
    not Workspaces.RootVolumeEncryptionEnabled
}

workspace_root_volume_encrypt_err = "Ensure that Workspace root volumes is encrypted." {
    not workspace_root_volume_encrypt
}

workspace_root_volume_encrypt_metadata := {
    "Policy Code": "PR-AWS-CLD-WS-002",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure that Workspace root volumes is encrypted.",
    "Policy Description": "It checks if encryption is enabled for workspace root volumes.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/workspaces.html#WorkSpaces.Client.describe_workspaces"
}


#
# PR-AWS-CLD-WS-003
# aws::workspaces::workspace

default workspace_directory_type = true

workspace_directory_type = false {
    directory := input.Directories[_]
    lower(directory.DirectoryType) == "simple_ad"
}

workspace_directory_type_err = "Ensure AWS WorkSpaces do not use directory type Simple AD." {
    not workspace_directory_type
}

workspace_directory_type_metadata := {
    "Policy Code": "PR-AWS-CLD-WS-003",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS WorkSpaces do not use directory type Simple AD.",
    "Policy Description": "It checks if Simple AD is used for workspace users. MS Active Directory is approved by GS to be used.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/workspaces.html#WorkSpaces.Client.describe_workspace_directories"
}


#
# PR-AWS-CLD-GLUE-001
#

default glue_catalog_encryption = true

glue_catalog_encryption = false {
    # lower(resource.Type) == "aws::glue::datacatalogencryptionsettings"
    not input.DataCatalogEncryptionSettings.ConnectionPasswordEncryption.ReturnConnectionPasswordEncrypted
}

glue_catalog_encryption = false {
    # lower(resource.Type) == "aws::glue::datacatalogencryptionsettings"
    not input.DataCatalogEncryptionSettings.EncryptionAtRest.CatalogEncryptionMode
}

glue_catalog_encryption = false {
    # lower(resource.Type) == "aws::glue::datacatalogencryptionsettings"
    lower(input.DataCatalogEncryptionSettings.EncryptionAtRest.CatalogEncryptionMode) != "sse-kms"
}

glue_catalog_encryption_err = "Ensure Glue Data Catalog encryption is enabled" {
    not glue_catalog_encryption
}

glue_catalog_encryption_metadata := {
    "Policy Code": "PR-AWS-CLD-GLUE-001",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure Glue Data Catalog encryption is enabled",
    "Policy Description": "Ensure that encryption at rest is enabled for your Amazon Glue Data Catalogs in order to meet regulatory requirements and prevent unauthorized users from getting access to sensitive data",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-datacatalogencryptionsettings-encryptionatrest.html"
}


#
# PR-AWS-CLD-GLUE-002
#

default glue_security_config = true

glue_security_config = false {
    # lower(resource.Type) == "aws::glue::securityconfiguration"
    not input.SecurityConfiguration.EncryptionConfiguration
}

glue_security_config = false {
    # lower(resource.Type) == "aws::glue::securityconfiguration"
    lower(input.SecurityConfiguration.EncryptionConfiguration.CloudWatchEncryption.CloudWatchEncryptionMode) != "sse-kms"
}

glue_security_config = false {
    # lower(resource.Type) == "aws::glue::securityconfiguration"
    lower(input.SecurityConfiguration.EncryptionConfiguration.JobBookmarksEncryption.JobBookmarksEncryptionMode) != "sse-kms"
}

glue_security_config = false {
    # lower(resource.Type) == "aws::glue::securityconfiguration"
    lower(input.SecurityConfiguration.EncryptionConfiguration.S3Encryption.S3EncryptionMode) != "sse-kms"
}

glue_security_config_err = "Ensure AWS Glue security configuration encryption is enabled" {
    not glue_security_config
}

glue_security_config_metadata := {
    "Policy Code": "PR-AWS-CLD-GLUE-002",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS Glue security configuration encryption is enabled",
    "Policy Description": "Ensure AWS Glue security configuration encryption is enabled",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-securityconfiguration-EncryptionConfiguration.html#cfn-glue-securityconfiguration-EncryptionConfiguration-s3encryptions"
}


#
# PR-AWS-CLD-GLUE-003
# aws::glue::securityconfiguration

default glue_encrypt_data_at_rest = true

glue_encrypt_data_at_rest = false {
    not input.SecurityConfiguration.EncryptionConfiguration.CloudWatchEncryption.CloudWatchEncryptionMode
}

glue_encrypt_data_at_rest = false {
    lower(input.SecurityConfiguration.EncryptionConfiguration.CloudWatchEncryption.CloudWatchEncryptionMode) == "disabled"
}

glue_encrypt_data_at_rest = false {
    not input.SecurityConfiguration.EncryptionConfiguration.JobBookmarksEncryption.JobBookmarksEncryptionMode
}

glue_encrypt_data_at_rest = false {
    lower(input.SecurityConfiguration.EncryptionConfiguration.JobBookmarksEncryption.JobBookmarksEncryptionMode) == "disabled"
}

glue_encrypt_data_at_rest = false {
    S3_Encryption := input.SecurityConfiguration.EncryptionConfiguration.S3Encryption[_]
    lower(S3_Encryption.S3EncryptionMode) == "disabled"
}

glue_encrypt_data_at_rest = false {
    
    S3_Encryption := input.SecurityConfiguration.EncryptionConfiguration.S3Encryption[_]
    not S3_Encryption.S3EncryptionMode
}

glue_encrypt_data_at_rest_err = "Ensure AWS Glue encrypt data at rest" {
    not glue_encrypt_data_at_rest
}

glue_encrypt_data_at_rest_metadata := {
    "Policy Code": "PR-AWS-CLD-GLUE-003",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS Glue encrypt data at rest.",
    "Policy Description": "It is to check that AWS Glue encryption at rest is enabled.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/glue.html#Glue.Client.get_security_configuration"
}


#
# PR-AWS-CLD-GLUE-004
# aws::glue::securityconfiguration
# AWS::KMS::Key

default glue_cmk_key = true

glue_cmk_key = false {
    X := input.TEST_ALL_06[_]
    Y := input.TEST_KMS[_]
    has_property(X.SecurityConfiguration.EncryptionConfiguration.JobBookmarksEncryption, "KmsKeyArn")
    X.SecurityConfiguration.EncryptionConfiguration.JobBookmarksEncryption.KmsKeyArn == Y.KeyMetadata.Arn
    Y.KeyMetadata.KeyManager != "CUSTOMER"
}

glue_cmk_key_err = "Ensure AWS Glue encrypt data at rest with GS managed Customer Master Key (CMK)." {
    not glue_cmk_key
}

glue_cmk_key_metadata := {
    "Policy Code": "PR-AWS-CLD-GLUE-004",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS Glue encrypt data at rest with GS managed Customer Master Key (CMK).",
    "Policy Description": "It is to check that GS managed CMK is used for AWS Glue encryption at rest.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/glue.html#Glue.Client.get_security_configuration"
}


#
# PR-AWS-CLD-GLUE-005
# aws::glue::securityconfiguration
# AWS::KMS::Key

default glue_cloudwatch_cmk_key = true

glue_cloudwatch_cmk_key = false {
    X := input.TEST_ALL_06[_]
    Y := input.TEST_KMS[_]
    has_property(X.SecurityConfiguration.EncryptionConfiguration.CloudWatchEncryption, "KmsKeyArn")
    X.SecurityConfiguration.EncryptionConfiguration.CloudWatchEncryption.KmsKeyArn == Y.KeyMetadata.Arn
    Y.KeyMetadata.KeyManager != "CUSTOMER"
}

glue_cloudwatch_cmk_key_err = "Ensure AWS Glue encrypt data at rest with GS managed Customer Master Key (CMK)." {
    not glue_cloudwatch_cmk_key
}

glue_cloudwatch_cmk_key_metadata := {
    "Policy Code": "PR-AWS-CLD-GLUE-005",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure CloudWatch encryption in AWS Glue is encrypted using GS-managed key.",
    "Policy Description": "It is to check that GS managed CMK is used while cloudwatch encryption instead of AWS provided keys.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/glue.html#Glue.Client.get_security_configuration"
}


#
# PR-AWS-CLD-AS-001
#

default as_volume_encrypted = true

as_volume_encrypted = false {
    # lower(resource.Type) == "aws::autoscaling::launchconfiguration"
    LaunchConfigurations := input.LaunchConfigurations[_]
    count([c | LaunchConfigurations.BlockDeviceMappings; c:=1]) == 0
}

as_volume_encrypted = false {
    # lower(resource.Type) == "aws::autoscaling::launchconfiguration"
    LaunchConfigurations := input.LaunchConfigurations[_]
    bdm := LaunchConfigurations.BlockDeviceMappings[j]
    not bdm.Ebs.Encrypted
}

as_volume_encrypted_err = "Ensure EBS volumes have encrypted launch configurations" {
    not as_volume_encrypted
}

as_volume_encrypted_metadata := {
    "Policy Code": "PR-AWS-CLD-AS-001",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure EBS volumes have encrypted launch configurations",
    "Policy Description": "Amazon Elastic Block Store (EBS) volumes allow you to create encrypted launch configurations when creating EC2 instances and auto scaling. When the entire EBS volume is encrypted, data stored at rest on the volume, disk I/O, snapshots created from the volume, and data in-transit between EBS and EC2 are all encrypted.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-launchconfig-blockdev-template.html#cfn-as-launchconfig-blockdev-template-encrypted"
}

#
# PR-AWS-CLD-AS-002
#

default as_elb_health_check = true

as_elb_health_check = false {
    # lower(resource.Type) == "aws::autoscaling::autoscalinggroup"
    AutoScalingGroups := input.AutoScalingGroups[_]
    count(AutoScalingGroups.LoadBalancerNames) != 0
    not AutoScalingGroups.HealthCheckType
}

as_elb_health_check = false {
    # lower(resource.Type) == "aws::autoscaling::autoscalinggroup"
    AutoScalingGroups := input.AutoScalingGroups[_]
    count(AutoScalingGroups.LoadBalancerNames) != 0
    lower(AutoScalingGroups.HealthCheckType) != "elb"
}

as_elb_health_check = false {
    # lower(resource.Type) == "aws::autoscaling::autoscalinggroup"
    AutoScalingGroups := input.AutoScalingGroups[_]
    count(AutoScalingGroups.TargetGroupARNs) != 0
    not AutoScalingGroups.HealthCheckType
}

as_elb_health_check = false {
    # lower(resource.Type) == "aws::autoscaling::autoscalinggroup"
    AutoScalingGroups := input.AutoScalingGroups[_]
    count(AutoScalingGroups.TargetGroupARNs) != 0
    lower(AutoScalingGroups.HealthCheckType) != "elb"
}

as_elb_health_check_err = "Ensure auto scaling groups associated with a load balancer use elastic load balancing health checks" {
    not as_elb_health_check
}

as_elb_health_check_metadata := {
    "Policy Code": "PR-AWS-CLD-AS-002",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure auto scaling groups associated with a load balancer use elastic load balancing health checks",
    "Policy Description": "If you configure an Auto Scaling group to use load balancer (ELB) health checks, it considers the instance unhealthy if it fails either the EC2 status checks or the load balancer health checks",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#cfn-as-group-healthchecktype"
}

#
# PR-AWS-CLD-AS-003
#

default as_http_token = true

as_http_token = false {
    # lower(resource.Type) == "aws::autoscaling::launchconfiguration"
    LaunchConfigurations := input.LaunchConfigurations[_]
    lower(LaunchConfigurations.MetadataOptions.HttpTokens) != "required"
}

as_http_token = false {
    # lower(resource.Type) == "aws::autoscaling::launchconfiguration"
    LaunchConfigurations := input.LaunchConfigurations[_]
    not LaunchConfigurations.MetadataOptions.HttpTokens
}

as_http_token_err = "Ensure EC2 Auto Scaling Group does not launch IMDSv1" {
    not as_http_token
}

as_http_token_metadata := {
    "Policy Code": "PR-AWS-CLD-AS-003",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure EC2 Auto Scaling Group does not launch IMDSv1",
    "Policy Description": "This control checks if EC2 instances use IMDSv1 instead of IMDSv2, this also applies to instances created in the ASG.IMDSv1 is vulnerable to Server Side Request Forgery (SSRF) vulnerabilities in web applications running on EC2, open Website Application Firewalls, open reverse proxies, and open layer 3 firewalls and NATs. IMDSv2 uses session-oriented requests every request is now protected by session authentication.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/cli/latest/reference/autoscaling/describe-launch-configurations.html"
}


#
# PR-AWS-CLD-CFR-001
#

default cf_sns = true

cf_sns = false {
    # lower(resource.Type) == "aws::cloudformation::stack"
    Stacks := input.Stacks[_]
    not Stacks.NotificationARNs
}

cf_sns = false {
    # lower(resource.Type) == "aws::cloudformation::stack"
    Stacks := input.Stacks[_]
    count(Stacks.NotificationARNs) == 0
}

cf_sns_err = "AWS CloudFormation stack configured without SNS topic" {
    not cf_sns
}

cf_sns_metadata := {
    "Policy Code": "PR-AWS-CLD-CFR-001",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS CloudFormation stack configured without SNS topic",
    "Policy Description": "This policy identifies CloudFormation stacks which are configured without SNS topic. It is recommended to configure Simple Notification Service (SNS) topic to be notified of CloudFormation stack status and changes.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-stack.html"
}

#
# PR-AWS-CLD-CFR-002
#

default cloudFormation_template_configured_with_stack_policy = true

cloudFormation_template_configured_with_stack_policy = false {
    # lower(resource.Type) == "AWS::CloudFormation::Stack"
    count(input.StackPolicyBody) == 0
}

cloudFormation_template_configured_with_stack_policy_err = "Ensure CloudFormation template is configured with stack policy." {
    not cloudFormation_template_configured_with_stack_policy
}

cloudFormation_template_configured_with_stack_policy_metadata := {
    "Policy Code": "PR-AWS-CLD-CFR-002",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure CloudFormation template is configured with stack policy.",
    "Policy Description": "In AWS IAM policy governs how much access/permission the stack has and if no policy is provided it assumes the permissions of the user running it.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cloudformation.html#CloudFormation.Client.get_stack_policy"
}

#
# PR-AWS-CLD-CFR-003
#

default cloudFormation_rollback_is_disabled = true

cloudFormation_rollback_is_disabled = false {
    # lower(resource.Type) == "AWS::CloudFormation::Stack"
    Stack := input.Stacks[_]
    Stack.DisableRollback == available_false_choices[_]
}

cloudFormation_rollback_is_disabled_err = "Ensure Cloudformation rollback is disabled." {
    not cloudFormation_rollback_is_disabled
}

cloudFormation_rollback_is_disabled_metadata := {
    "Policy Code": "PR-AWS-CLD-CFR-003",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure Cloudformation rollback is disabled.",
    "Policy Description": "It checks the stack rollback setting, in case of a failure do not rollback the entire stack. We can use change sets run the stack again, after fixing the template. Resources which are already provisioned won't be re-created.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cloudformation.html#CloudFormation.Client.describe_stacks"
}

#
# PR-AWS-CLD-CFR-004
#

default role_arn_exist = true

role_arn_exist = false {
    # lower(resource.Type) == "AWS::CloudFormation::Stack"
    Stack := input.Stacks[_]
    not Stack.RoleARN
}

role_arn_exist_err = "Ensure an IAM policy is defined with the stack." {
    not role_arn_exist
}

role_arn_exist_metadata := {
    "Policy Code": "PR-AWS-CLD-CFR-004",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure an IAM policy is defined with the stack.",
    "Policy Description": "Stack policy protects resources from accidental updates, the policy included resources which shouldn't be updated during the template provisioning process.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cloudformation.html#CloudFormation.Client.describe_stacks"
}

#
# PR-AWS-CLD-CFR-005
#

default stack_with_not_all_capabilities = true

stack_with_not_all_capabilities = false {
    # lower(resource.Type) == "AWS::CloudFormation::Stack"
    Stack := input.Stacks[_]
    contains(Stack.Capabilities[_], "*")
}

stack_with_not_all_capabilities_err = "Ensure capabilities in stacks do not have * in it." {
    not stack_with_not_all_capabilities
}

stack_with_not_all_capabilities_metadata := {
    "Policy Code": "PR-AWS-CLD-CFR-005",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure capabilities in stacks do not have * in it.",
    "Policy Description": "A CloudFormation stack needs certain capability, It is recommended to configure the stack with capabilities not all capabilities (*) should be configured. This will give the stack unlimited access.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cloudformation.html#CloudFormation.Client.describe_stacks"
}

#
# PR-AWS-CLD-CFR-006
#

default termination_protection_in_stacks_is_enabled = true

termination_protection_in_stacks_is_enabled = false {
    # lower(resource.Type) == "AWS::CloudFormation::Stack"
    Stack := input.Stacks[_]
    Stack.EnableTerminationProtection == available_false_choices[_]
}

termination_protection_in_stacks_is_enabled_err = "Ensure termination protection in stacks is enabled." {
    not termination_protection_in_stacks_is_enabled
}

termination_protection_in_stacks_is_enabled_metadata := {
    "Policy Code": "PR-AWS-CLD-CFR-006",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure termination protection in stacks is enabled.",
    "Policy Description": "It checks if the stack is protected against accidental termination which may lead to deletion of critical resources.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cloudformation.html#CloudFormation.Client.describe_stacks"
}


#
# PR-AWS-CLD-CFG-001
#

default config_all_resource = true

config_all_resource = false {
    # lower(resource.Type) == "aws::config::configurationrecorder"
    ConfigurationRecorders := input.ConfigurationRecorders[_]
    not ConfigurationRecorders.recordingGroup
}

config_all_resource = false {
    # lower(resource.Type) == "aws::config::configurationrecorder"
    ConfigurationRecorders := input.ConfigurationRecorders[_]
    ConfigurationRecorders.recordingGroup
    not ConfigurationRecorders.recordingGroup.allSupported
}

config_all_resource = false {
    # lower(resource.Type) == "aws::config::configurationrecorder"
    ConfigurationRecorders := input.ConfigurationRecorders[_]
    ConfigurationRecorders.recordingGroup
    not ConfigurationRecorders.recordingGroup.includeGlobalResourceTypes
}

config_all_resource_err = "AWS Config must record all possible resources" {
    not config_all_resource
}

config_all_resource_metadata := {
    "Policy Code": "PR-AWS-CLD-CFG-001",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS Config must record all possible resources",
    "Policy Description": "This policy identifies resources for which AWS Config recording is enabled but recording for all possible resources are disabled. AWS Config provides an inventory of your AWS resources and a history of configuration changes to these resources. You can use AWS Config to define rules that evaluate these configurations for compliance. Hence, it is important to enable this feature.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-config-configurationrecorder.html"
}


#
# PR-AWS-CLD-CFG-002
#

default aws_config_configuration_aggregator = true

aws_config_configuration_aggregator = false {
    # lower(resource.Type) == "aws::config::configurationaggregator".
    ConfigurationAggregators := input.ConfigurationAggregators[_]
    AccountAggregationSources := ConfigurationAggregators.AccountAggregationSources[_]
    not AccountAggregationSources.AllAwsRegions
}

aws_config_configuration_aggregator_err = "Ensure AWS config is enabled in all regions" {
    not aws_config_configuration_aggregator
}

aws_config_configuration_aggregator_metadata := {
    "Policy Code": "PR-AWS-CLD-CFG-002",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS config is enabled in all regions",
    "Policy Description": "AWS Config is a web service that performs the configuration management of supported AWS resources within your account and delivers log files to you.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-config-configurationaggregator-accountaggregationsource.html#cfn-config-configurationaggregator-accountaggregationsource-allawsregions"
}


#
# PR-AWS-CLD-CFG-003
#

default aws_config_recorder_status = true

aws_config_recorder_status = false {
    # lower(resource.Type) == "aws::config::configurationrecorder".
    ConfigurationRecordersStatus := input.ConfigurationRecordersStatus[_]
    ConfigurationRecordersStatus.recording == true
    lower(ConfigurationRecordersStatus.lastStatus) == "failure"
}

aws_config_recorder_status_err = "Ensure AWS Config do not fails to deliver log files" {
    not aws_config_recorder_status
}

aws_config_recorder_status_metadata := {
    "Policy Code": "PR-AWS-CLD-CFG-003",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS Config does not fail to deliver log files",
    "Policy Description": "This policy identifies AWS Configs failing to deliver its log files to the specified S3 bucket. It happens when it doesn't have sufficient permissions to complete the operation. To deliver information to S3 bucket, AWS Config needs to assume an IAM role that manages the permissions required to access the designated S3 bucket.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/config.html#ConfigService.Client.describe_configuration_recorders"
}

#
# PR-AWS-CLD-CFG-004
#

default config_includes_global_resources = true

config_includes_global_resources = false {
    # lower(resource.Type) == "aws::config::configurationrecorder".
    ConfigurationRecorders := input.ConfigurationRecorders[_]
    ConfigurationRecorders.recordingGroup.includeGlobalResourceTypes == available_false_choices[_]
}

config_includes_global_resources_err = "Ensure AWS Config includes global resources types (IAM)." {
    not config_includes_global_resources
}

config_includes_global_resources_metadata := {
    "Policy Code": "PR-AWS-CLD-CFG-004",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS Config includes global resources types (IAM).",
    "Policy Description": "It checks that global resource types are included in AWS Config.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/config.html#ConfigService.Client.describe_configuration_recorders"
}

#
# PR-AWS-CLD-KNS-001
#
default kinesis_encryption = true

kinesis_encryption = false {
    # lower(resource.Type) == "aws::kinesis::stream"
    not input.StreamDescription.StreamDescription.EncryptionType
}

kinesis_encryption = false {
    # lower(resource.Type) == "aws::kinesis::stream"
    lower(input.StreamDescription.StreamDescription.EncryptionType) == "none"
}

kinesis_encryption_err = "AWS Kinesis streams are not encrypted using Server Side Encryption" {
    not kinesis_encryption
}

kinesis_encryption_metadata := {
    "Policy Code": "PR-AWS-CLD-KNS-001",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS Kinesis streams are not encrypted using Server Side Encryption",
    "Policy Description": "This Policy identifies the AWS Kinesis streams which are not encrypted using Server Side Encryption. Server Side Encryption is used to encrypt your sensitive data before it is written to the Kinesis stream storage layer and decrypted after it is retrieved from storage.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-kinesis-stream.html#aws-resource-kinesis-stream--examples"
}


#
# PR-AWS-CLD-KNS-002
#

default kinesis_encryption_kms = null

kinesis_encryption_kms = false {
    # lower(resource.Type) == "aws::kinesis::stream"
    not input.StreamDescription.EncryptionType
}

kinesis_encryption_kms = false {
    # lower(resource.Type) == "aws::kinesis::stream"
    lower(input.StreamDescription.EncryptionType) == "kms"
    contains(lower(input.StreamDescription.KeyId), "aws/kinesis")
}

kinesis_encryption_kms = true {
    # lower(resource.Type) == "aws::kinesis::stream"
    lower(input.StreamDescription.EncryptionType) == "kms"
    not contains(lower(input.StreamDescription.KeyId), "aws/kinesis")
}

kinesis_encryption_kms_err = "AWS Kinesis streams encryption using default KMS keys instead of Customer's Managed Master Keys" {
    not kinesis_encryption_kms
}

kinesis_encryption_kms_metadata := {
    "Policy Code": "PR-AWS-CLD-KNS-002",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS Kinesis streams encryption using default KMS keys instead of Customer's Managed Master Keys",
    "Policy Description": "This policy identifies the AWS Kinesis streams which are encrypted with default KMS keys and not with Master Keys managed by Customer. It is a best practice to use customer managed Master Keys to encrypt your Amazon Kinesis streams data. It gives you full control over the encrypted data.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-kinesis-stream.html#aws-resource-kinesis-stream--examples"
}


#
# PR-AWS-CLD-KNS-003
# aws::kinesis::stream

default kinesis_gs_kms_key = true

kinesis_gs_kms_key = false {
    X := input.TEST_ALL_11[_]
    X.StreamDescription.EncryptionType == "KMS"
    Y := input.TEST_KMS[_]
    X.StreamDescription.KeyId == Y.KeyMetadata.KeyId
    Y.KeyMetadata.KeyManager != "CUSTOMER"
}

kinesis_gs_kms_key = false {
    X := input.TEST_ALL_11[_]
    X.StreamDescription.EncryptionType == "KMS"
    Y := input.TEST_KMS[_]
    X.StreamDescription.KeyId == Y.KeyMetadata.Arn
    Y.KeyMetadata.KeyManager != "CUSTOMER"
}

kinesis_gs_kms_key_err = "Ensure Kinesis streams are encrypted using dedicated GS managed KMS key." {
    not kinesis_gs_kms_key
}

kinesis_gs_kms_key_metadata := {
    "Policy Code": "PR-AWS-CLD-KNS-003",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure Kinesis streams are encrypted using dedicated GS managed KMS key.",
    "Policy Description": "It is to check only GS managed CMKs are used to encrypt Kinesis Data Streams.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/kinesis.html#Kinesis.Client.describe_stream"
}


#
# PR-AWS-CLD-MQ-001
#
default mq_publicly_accessible = true

mq_publicly_accessible = false {
    # lower(resource.Type) == "aws::amazonmq::broker"
    input.PubliclyAccessible == true
}

mq_publicly_accessible = false {
    # lower(resource.Type) == "aws::amazonmq::broker"
    lower(input.PubliclyAccessible) == "true"
}

mq_publicly_accessible_err = "AWS MQ is publicly accessible" {
    not mq_publicly_accessible
}


mq_publicly_accessible_metadata := {
    "Policy Code": "PR-AWS-CLD-MQ-001",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS MQ is publicly accessible",
    "Policy Description": "This policy identifies the AWS MQ brokers which are publicly accessible. It is advisable to use MQ brokers privately only from within your AWS Virtual Private Cloud (VPC). Ensure that the AWS MQ brokers provisioned in your AWS account are not publicly accessible from the Internet to avoid sensitive data exposure and minimize security risks.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-broker.html#cfn-amazonmq-broker-publiclyaccessible"
}


#
# PR-AWS-CLD-MQ-002
#
default mq_logging_enable = true

mq_logging_enable = false {
    # lower(resource.Type) == "aws::amazonmq::broker"
    not input.Logs.General
}

mq_logging_enable_err = "Ensure Amazon MQ Broker logging is enabled" {
    not mq_logging_enable
}

mq_logging_enable_metadata := {
    "Policy Code": "PR-AWS-CLD-MQ-002",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure Amazon MQ Broker logging is enabled",
    "Policy Description": "Amazon MQ is integrated with CloudTrail and provides a record of the Amazon MQ calls made by a user, role, or AWS service. It supports logging both the request parameters and the responses for APIs as events in CloudTrail",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-broker.html#cfn-amazonmq-broker-publiclyaccessible"
}

#
# PR-AWS-CLD-MQ-003
#

default mq_activemq_approved_engine_version = true

mq_activemq_approved_engine_version = false {
    # lower(resource.Type) == "aws::amazonmq::broker"
    lower(input.EngineType) == "activemq"
    not startswith(input.EngineVersion, "5.16")
}

mq_activemq_approved_engine_version_err = "Ensure ActiveMQ engine version is approved by GS." {
    not mq_activemq_approved_engine_version
}

mq_activemq_approved_engine_version_metadata := {
    "Policy Code": "PR-AWS-CLD-MQ-003",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure ActiveMQ engine version is approved by GS.",
    "Policy Description": "It is used to check only firm approved version of ActiveMQ is being used.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/mq.html#MQ.Client.describe_broker"
}

#
# PR-AWS-CLD-MQ-004
#

default mq_rabbitmq_approved_engine_version = true

mq_rabbitmq_approved_engine_version = false {
    # lower(resource.Type) == "aws::amazonmq::broker"
    lower(input.EngineType) == "rabbitmq"
    not startswith(input.EngineVersion, "3.8")
}

mq_rabbitmq_approved_engine_version_err = "Ensure RabbitMQ engine version is approved by GS." {
    not mq_rabbitmq_approved_engine_version
}

mq_rabbitmq_approved_engine_version_metadata := {
    "Policy Code": "PR-AWS-CLD-MQ-004",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure RabbitMQ engine version is approved by GS.",
    "Policy Description": "It is used to check only firm approved version of RabbitMQ is being used.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/mq.html#MQ.Client.describe_broker"
}

#
# PR-AWS-CLD-MQ-005
#

default audit_logs_published_to_cloudWatch = true

audit_logs_published_to_cloudWatch = false {
    # lower(resource.Type) == "aws::amazonmq::broker"
    lower(input.EngineType) == "activemq"
    lower(input.Logs.Audit) == available_false_choices[_]
}

audit_logs_published_to_cloudWatch = false {
    # lower(resource.Type) == "aws::amazonmq::broker"
    not input.Logs.Audit
}

audit_logs_published_to_cloudWatch_err = "Ensure General and Audit logs are published to CloudWatch." {
    not audit_logs_published_to_cloudWatch
}

audit_logs_published_to_cloudWatch_metadata := {
    "Policy Code": "PR-AWS-CLD-MQ-005",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure General and Audit logs are published to CloudWatch.",
    "Policy Description": "It is used to check that Amazon MQ is configured to push logs to CloudWatch in order to enhance troubleshooting in case of issues. It does not apply to RabbitMQ brokers.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/mq.html#MQ.Client.describe_broker"
}

#
# PR-AWS-CLD-R53-001
#

default route_healthcheck_disable = true

route_healthcheck_disable = false {
    # lower(resource.Type) == "aws::route53::recordsetgroup"
    ResourceRecordSets := input.ResourceRecordSets[j]
    not ResourceRecordSets.AliasTarget.EvaluateTargetHealth
}

route_healthcheck_disable_err = "Ensure Route53 DNS evaluateTargetHealth is enabled" {
    not route_healthcheck_disable
}

route_healthcheck_disable_metadata := {
    "Policy Code": "PR-AWS-CLD-R53-001",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure Route53 DNS evaluateTargetHealth is enabled",
    "Policy Description": "The EvaluateTargetHealth of Route53 is not enabled, an alias record can't inherits the health of the referenced AWS resource, such as an ELB load balancer or another record in the hosted zone.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html"
}


#
# PR-AWS-CLD-WAF-001
#

default waf_log4j_vulnerability = true

waf_log4j_vulnerability = false {
    # lower(resource.Type) == "aws::wafv2::webacl"
    Rules := input.WebACL.Rules[_]
    lower(Rules.Statement.ManagedRuleGroupStatement.Name) == "awsmanagedrulesknownbadinputsruleset"
    ExcludedRules := Rules.Statement.ManagedRuleGroupStatement.ExcludedRules[_]
    lower(ExcludedRules.Name) == "log4jrce"

}

waf_log4j_vulnerability = false {
    # lower(resource.Type) == "aws::wafv2::webacl"
    Rules := input.WebACL.Rules[_]
    not has_property(Rules.OverrideAction, "None")
}

waf_log4j_vulnerability_err = "JMSAppender in Log4j 1.2 is vulnerable to deserialization of untrusted data when the attacker has write access to the Log4j configuration" {
    not waf_log4j_vulnerability
}

waf_log4j_vulnerability_metadata := {
    "Policy Code": "PR-AWS-CLD-WAF-001",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "JMSAppender in Log4j 1.2 is vulnerable to deserialization of untrusted data when the attacker has write access to the Log4j configuration",
    "Policy Description": "Apache Log4j2 2.0-beta9 through 2.12.1 and 2.13.0 through 2.15.0 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-managedrulegroupstatement.html#cfn-wafv2-webacl-managedrulegroupstatement-name"
}


#
# PR-AWS-CLD-INS-001
#

default ins_package = true

ins_package = false {
    # lower(resource.Type) == "aws::wafv2::webacl"
    rulesPackageArns := input.rulesPackageArns
    count([c | lower(rulesPackageArns[_]) == lower(rules_packages[_]); c:=1]) == 0
}

ins_package = false {
    # lower(resource.Type) == "aws::wafv2::webacl"
    count(input.rulesPackageArns) == 0
}

ins_package_err = "Enable AWS Inspector to detect Vulnerability" {
    not ins_package
}

ins_package_metadata := {
    "Policy Code": "PR-AWS-CLD-INS-001",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Enable AWS Inspector to detect Vulnerability",
    "Policy Description": "Enable AWS Inspector to detect Vulnerability",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-inspector-assessmenttemplate.html"
}

#
# PR-AWS-CLD-APS-001
#

default appsync_not_configured_with_firewall_v2 = true

appsync_not_configured_with_firewall_v2 = false {
    # lower(resource.Type) == "aws::appsync::graphql"
    not input.graphqlApi.wafWebAclArn
}

appsync_not_configured_with_firewall_v2_err = "Ensure AppSync is configured with AWS Web Application Firewall v2." {
    not appsync_not_configured_with_firewall_v2
}

appsync_not_configured_with_firewall_v2_metadata := {
    "Policy Code": "PR-AWS-CLD-APS-001",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AppSync is configured with AWS Web Application Firewall v2.",
    "Policy Description": "Enable the AWS WAF service on AppSync to protect against application layer attacks. To block malicious requests to your AppSync, define the block criteria in the WAF web access control list (web ACL).",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/appsync.html#AppSync.Client.get_graphql_api"
}


#
# PR-AWS-CLD-DS-001
# AWS::DirectoryService::MicrosoftAD
# AWS::DirectoryService::SimpleAD
# aws::ec2::vpc

default directory_dhcp_option = true

directory_dhcp_option = false {
    X := input.TEST_DIRECTORYSERVICE[_]
    directory := X.DirectoryDescriptions[_]
    Y := input.TEST_EC2_04[_]
    vpc := Y.Vpcs[_]
    not vpc.DhcpOptionsId
    directory.VpcSettings.VpcId == vpc.VpcId
}

directory_dhcp_option_err = "Ensure AWS Directory Service DHCP options is set for the VPC hosting managed AD." {
    not directory_dhcp_option
}

directory_dhcp_option_metadata := {
    "Policy Code": "PR-AWS-CLD-AD-001",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS Directory Service DHCP options is set for the VPC hosting managed AD.",
    "Policy Description": "It checks if the VPC hosting the managed AD has DHCP options created. DHCP options allow any instances in that VPC to point to the specified domain and DNS servers to resolve their domain names.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ds.html#DirectoryService.Client.describe_directories",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_vpcs"
}


#
# PR-AWS-CLD-DS-002
# AWS::DirectoryService::MicrosoftAD
# AWS::DirectoryService::SimpleAD
# aws::ec2::vpc

default directory_default_vpc = true

directory_default_vpc = false {
    X := input.TEST_DIRECTORYSERVICE[_]
    directory := X.DirectoryDescriptions[_]
    Y := input.TEST_EC2_04[_]
    vpc := Y.Vpcs[_]
    vpc.IsDefault == true
    directory.VpcSettings.VpcId == vpc.VpcId
}

directory_default_vpc_err = "Ensure AWS Directory Service is not launched using default VPC." {
    not directory_default_vpc
}

directory_default_vpc_metadata := {
    "Policy Code": "PR-AWS-CLD-AD-002",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS Directory Service is not launched using default VPC.",
    "Policy Description": "It checks if default VPC is being used. Default VPC are provided by AWS and not hardened hence shouldn't be used.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ds.html#DirectoryService.Client.describe_directories",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_vpcs"
}


#
# PR-AWS-CLD-DS-003
# AWS::DirectoryService::MicrosoftAD
# AWS::DirectoryService::SimpleAD
# aws::ec2::instance

default directory_security_group = true

directory_security_group = false {
    X := input.TEST_DIRECTORYSERVICE[_]
    directory := X.DirectoryDescriptions[_]
    Y := input.TEST_EC2_01[_]
    Reservation := Y.Reservations[_]
    Instance := Reservation.Instances[_]
    security_grp := Instance.SecurityGroups[_]
    directory.VpcSettings.SecurityGroupId == security_grp.GroupId
}

directory_security_group_err = "Ensure the Security groups attached to domain controllers for AWS Directory Service are not used by other instances." {
    not directory_security_group
}

directory_security_group_metadata := {
    "Policy Code": "PR-AWS-CLD-AD-003",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure the Security groups attached to domain controllers for AWS Directory Service are not used by other instances.",
    "Policy Description": "It checks if the security groups used by Domain controllers for AD are not shared with other resource interfaces. This is the best practice for setting up Domain controllers.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ds.html#DirectoryService.Client.describe_directories",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_instances"
}


#
# PR-AWS-CLD-DS-004
# AWS::DirectoryService::MicrosoftAD
# AWS::DirectoryService::SimpleAD
# aws::ec2::instance

default directory_subnet = true

directory_subnet = false {
    X := input.TEST_DIRECTORYSERVICE[_]
    directory := X.DirectoryDescriptions[_]
    Y := input.TEST_EC2_01[_]
    Reservation := Y.Reservations[_]
    Instance := Reservation.Instances[_]
    Subnet := directory.VpcSettings.SubnetIds[_]
    Subnet == Instance.SubnetId
}

directory_subnet_err = "Ensure the subnets used by the domain controllers for AWS Directory Service are not used by other instances." {
    not directory_subnet
}

directory_subnet_metadata := {
    "Policy Code": "PR-AWS-CLD-AD-004",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure the subnets used by the domain controllers for AWS Directory Service are not used by other instances.",
    "Policy Description": "It checks if subnets used by Domain controllers for AD are segregated from the user network. This is the best practice for setting up Domain controllers.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ds.html#DirectoryService.Client.describe_directories",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_instances"
}