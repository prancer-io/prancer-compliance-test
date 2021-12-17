package rule

has_property(parent_object, target_property) { 
	_ = parent_object[target_property]
}


# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-apigateway-stage.html

#
# PR-AWS-CFR-SM-001
#

default secret_manager_kms = null

aws_issue["secret_manager_kms"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::secretsmanager::secret"
    not resource.Properties.KmsKeyId
}

source_path[{"secret_manager_kms": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::secretsmanager::secret"
    not resource.Properties.KmsKeyId
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "KmsKeyId"]
        ],
    }
}

aws_issue["secret_manager_kms"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::secretsmanager::secret"
    count(resource.Properties.KmsKeyId) == 0
}

source_path[{"secret_manager_kms": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::secretsmanager::secret"
    count(resource.Properties.KmsKeyId) == 0
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "KmsKeyId"]
        ],
    }
}

secret_manager_kms {
    lower(input.Resources[i].Type) == "aws::secretsmanager::secret"
    not aws_issue["secret_manager_kms"]
}

secret_manager_kms = false {
    aws_issue["secret_manager_kms"]
}

secret_manager_kms_err = "Ensure that Secrets Manager secret is encrypted using KMS" {
    aws_issue["secret_manager_kms"]
}

secret_manager_kms_metadata := {
    "Policy Code": "PR-AWS-CFR-SM-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure that Secrets Manager secret is encrypted using KMS",
    "Policy Description": "Ensure that your Amazon Secrets Manager secrets (i.e. database credentials, API keys, OAuth tokens, etc) are encrypted with Amazon KMS Customer Master Keys instead of default encryption keys that Secrets Manager service creates for you, in order to have a more control over secret data encryption and decryption process",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-secretsmanager-secret.html"
}

#
# PR-AWS-CFR-LG-001
#

default log_group_encryption = null

aws_issue["log_group_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::logs::loggroup"
    not resource.Properties.KmsKeyId
}

source_path[{"log_group_encryption": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::logs::loggroup"
    not resource.Properties.KmsKeyId
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "KmsKeyId"]
        ],
    }
}

aws_issue["log_group_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::logs::loggroup"
    count(resource.Properties.KmsKeyId) == 0
}

source_path[{"log_group_encryption": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::logs::loggroup"
    count(resource.Properties.KmsKeyId) == 0
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "KmsKeyId"]
        ],
    }
}

aws_issue["log_group_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::logs::loggroup"
    resource.Properties.KmsKeyId == null
}

source_path[{"log_group_encryption": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::logs::loggroup"
    resource.Properties.KmsKeyId == null
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "KmsKeyId"]
        ],
    }
}

log_group_encryption {
    lower(input.Resources[i].Type) == "aws::logs::loggroup"
    not aws_issue["log_group_encryption"]
}

log_group_encryption = false {
    aws_issue["log_group_encryption"]
}

log_group_encryption_err = "Ensure CloudWatch log groups are encrypted with KMS CMKs" {
    aws_issue["log_group_encryption"]
}

log_group_encryption_metadata := {
    "Policy Code": "PR-AWS-CFR-LG-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure CloudWatch log groups are encrypted with KMS CMKs",
    "Policy Description": "CloudWatch log groups are encrypted by default. However, utilizing KMS CMKs gives you more control over key rotation and provides auditing visibility into key usage.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-loggroup.html"
}

#
# PR-AWS-CFR-LG-002
#

default log_group_retention = null

aws_issue["log_group_retention"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::logs::loggroup"
    not resource.Properties.RetentionInDays
}

source_path[{"log_group_retention": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::logs::loggroup"
    not resource.Properties.RetentionInDays
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "RetentionInDays"]
        ],
    }
}

log_group_retention {
    lower(input.Resources[i].Type) == "aws::logs::loggroup"
    not aws_issue["log_group_retention"]
}

log_group_retention = false {
    aws_issue["log_group_retention"]
}

log_group_retention_err = "Ensure CloudWatch log groups has retention days defined" {
    aws_issue["log_group_retention"]
}

log_group_retention_metadata := {
    "Policy Code": "PR-AWS-CFR-LG-002",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure CloudWatch log groups has retention days defined",
    "Policy Description": "Ensure that your web-tier CloudWatch log group has the retention period feature configured in order to establish how long log events are kept in AWS CloudWatch Logs",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-loggroup.html"
}


#
# PR-AWS-CFR-WS-001
#

default workspace_volume_encrypt = null

aws_issue["workspace_volume_encrypt"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::workspaces::workspace"
    not resource.Properties.UserVolumeEncryptionEnabled
}

source_path[{"workspace_volume_encrypt": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::workspaces::workspace"
    not resource.Properties.UserVolumeEncryptionEnabled
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "UserVolumeEncryptionEnabled"]
        ],
    }
}

aws_issue["workspace_volume_encrypt"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::workspaces::workspace"
    lower(resource.Properties.UserVolumeEncryptionEnabled) == "false"
}

source_path[{"workspace_volume_encrypt": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::workspaces::workspace"
    lower(resource.Properties.UserVolumeEncryptionEnabled) == "false"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "UserVolumeEncryptionEnabled"]
        ],
    }
}

workspace_volume_encrypt {
    lower(input.Resources[i].Type) == "aws::workspaces::workspace"
    not aws_issue["workspace_volume_encrypt"]
}

workspace_volume_encrypt = false {
    aws_issue["workspace_volume_encrypt"]
}

workspace_volume_encrypt_err = "Ensure that Workspace user volumes is encrypted" {
    aws_issue["workspace_volume_encrypt"]
}

workspace_volume_encrypt_metadata := {
    "Policy Code": "PR-AWS-CFR-WS-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure that Workspace user volumes is encrypted",
    "Policy Description": "Ensure that your Amazon WorkSpaces storage volumes are encrypted in order to meet security and compliance requirements. Your data is transparently encrypted while being written and transparently decrypted while being read from your storage volumes, therefore the encryption process does not require any additional action from you",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-workspaces-workspace.html"
}



#
# PR-AWS-CFR-GLUE-001
#

default glue_catalog_encryption = null

aws_issue["glue_catalog_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::glue::datacatalogencryptionsettings"
    not resource.Properties.DataCatalogEncryptionSettings.ConnectionPasswordEncryption.ReturnConnectionPasswordEncrypted
}

source_path[{"glue_catalog_encryption": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::glue::datacatalogencryptionsettings"
    not resource.Properties.DataCatalogEncryptionSettings.ConnectionPasswordEncryption.ReturnConnectionPasswordEncrypted
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "DataCatalogEncryptionSettings", "ConnectionPasswordEncryption", "ReturnConnectionPasswordEncrypted"]
        ],
    }
}

aws_issue["glue_catalog_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::glue::datacatalogencryptionsettings"
    lower(resource.Properties.DataCatalogEncryptionSettings.ConnectionPasswordEncryption.ReturnConnectionPasswordEncrypted) == "false"
}

source_path[{"glue_catalog_encryption": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::glue::datacatalogencryptionsettings"
    lower(resource.Properties.DataCatalogEncryptionSettings.ConnectionPasswordEncryption.ReturnConnectionPasswordEncrypted) == "false"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "DataCatalogEncryptionSettings", "ConnectionPasswordEncryption", "ReturnConnectionPasswordEncrypted"]
        ],
    }
}

aws_issue["glue_catalog_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::glue::datacatalogencryptionsettings"
    not resource.Properties.DataCatalogEncryptionSettings.EncryptionAtRest.CatalogEncryptionMode
}

source_path[{"glue_catalog_encryption": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::glue::datacatalogencryptionsettings"
    not resource.Properties.DataCatalogEncryptionSettings.EncryptionAtRest.CatalogEncryptionMode
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "DataCatalogEncryptionSettings", "EncryptionAtRest", "CatalogEncryptionMode"]
        ],
    }
}

aws_issue["glue_catalog_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::glue::datacatalogencryptionsettings"
    lower(resource.Properties.DataCatalogEncryptionSettings.EncryptionAtRest.CatalogEncryptionMode) != "sse-kms"
}

source_path[{"glue_catalog_encryption": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::glue::datacatalogencryptionsettings"
    lower(resource.Properties.DataCatalogEncryptionSettings.EncryptionAtRest.CatalogEncryptionMode) != "sse-kms"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "DataCatalogEncryptionSettings", "EncryptionAtRest", "CatalogEncryptionMode"]
        ],
    }
}

glue_catalog_encryption {
    lower(input.Resources[i].Type) == "aws::glue::datacatalogencryptionsettings"
    not aws_issue["glue_catalog_encryption"]
}

glue_catalog_encryption = false {
    aws_issue["glue_catalog_encryption"]
}

glue_catalog_encryption_err = "Ensure Glue Data Catalog encryption is enabled" {
    aws_issue["glue_catalog_encryption"]
}

glue_catalog_encryption_metadata := {
    "Policy Code": "PR-AWS-CFR-GLUE-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure Glue Data Catalog encryption is enabled",
    "Policy Description": "Ensure that encryption at rest is enabled for your Amazon Glue Data Catalogs in order to meet regulatory requirements and prevent unauthorized users from getting access to sensitive data",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-datacatalogencryptionsettings-encryptionatrest.html"
}



#
# PR-AWS-CFR-GLUE-002
#

default glue_security_config = null

aws_issue["glue_security_config"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::glue::securityconfiguration"
    not resource.Properties.EncryptionConfiguration
}

source_path[{"glue_security_config": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::glue::securityconfiguration"
    not resource.Properties.EncryptionConfiguration
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "EncryptionConfiguration"]
        ],
    }
}

aws_issue["glue_security_config"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::glue::securityconfiguration"
    lower(resource.Properties.EncryptionConfiguration.CloudWatchEncryption.CloudWatchEncryptionMode) != "SSE-KMS"
}

source_path[{"glue_security_config": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::glue::securityconfiguration"
    lower(resource.Properties.EncryptionConfiguration.CloudWatchEncryption.CloudWatchEncryptionMode) != "SSE-KMS"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "EncryptionConfiguration", "CloudWatchEncryption", "CloudWatchEncryptionMode"]
        ],
    }
}

aws_issue["glue_security_config"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::glue::securityconfiguration"
    lower(resource.Properties.EncryptionConfiguration.JobBookmarksEncryption.JobBookmarksEncryptionMode) != "SSE-KMS"
}

source_path[{"glue_security_config": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::glue::securityconfiguration"
    lower(resource.Properties.EncryptionConfiguration.JobBookmarksEncryption.JobBookmarksEncryptionMode) != "SSE-KMS"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "EncryptionConfiguration", "JobBookmarksEncryption", "JobBookmarksEncryptionMode"]
        ],
    }
}

aws_issue["glue_security_config"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::glue::securityconfiguration"
    lower(resource.Properties.EncryptionConfiguration.S3Encryptions.S3EncryptionMode) != "SSE-KMS"
}

source_path[{"glue_security_config": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::glue::securityconfiguration"
    lower(resource.Properties.EncryptionConfiguration.S3Encryptions.S3EncryptionMode) != "SSE-KMS"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "EncryptionConfiguration", "S3Encryptions", "S3EncryptionMode"]
        ],
    }
}

glue_security_config {
    lower(input.Resources[i].Type) == "aws::glue::securityconfiguration"
    not aws_issue["glue_security_config"]
}

glue_security_config = false {
    aws_issue["glue_security_config"]
}

glue_security_config_err = "Ensure AWS Glue security configuration encryption is enabled" {
    aws_issue["glue_security_config"]
}

glue_security_config_metadata := {
    "Policy Code": "PR-AWS-CFR-GLUE-002",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure AWS Glue security configuration encryption is enabled",
    "Policy Description": "Ensure AWS Glue security configuration encryption is enabled",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-glue-securityconfiguration-encryptionconfiguration.html#cfn-glue-securityconfiguration-encryptionconfiguration-s3encryptions"
}

#
# PR-AWS-CFR-AS-001
#

default as_volume_encrypted = null

aws_issue["as_volume_encrypted"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::autoscaling::launchconfiguration"
    count([c | resource.Properties.BlockDeviceMappings; c:=1]) == 0
}

source_path[{"as_volume_encrypted": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::autoscaling::launchconfiguration"
    count([c | resource.Properties.BlockDeviceMappings; c:=1]) == 0
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "BlockDeviceMappings"]
        ],
    }
}

aws_bool_issue["as_volume_encrypted"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::autoscaling::launchconfiguration"
    bdm := resource.Properties.BlockDeviceMappings[j]
    not bdm.Ebs.Encrypted
}

source_path[{"as_volume_encrypted": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::autoscaling::launchconfiguration"
    bdm := resource.Properties.BlockDeviceMappings[j]
    not bdm.Ebs.Encrypted
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "BlockDeviceMappings", j, "Ebs", "Encrypted"]
        ],
    }
}

aws_issue["as_volume_encrypted"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::autoscaling::launchconfiguration"
    bdm := resource.Properties.BlockDeviceMappings[j]
    lower(bdm.Ebs.Encrypted) != "true"
}

source_path[{"as_volume_encrypted": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::autoscaling::launchconfiguration"
    bdm := resource.Properties.BlockDeviceMappings[j]
    lower(bdm.Ebs.Encrypted) != "true"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "BlockDeviceMappings", j, "Ebs", "Encrypted"]
        ],
    }
}

as_volume_encrypted {
    lower(input.Resources[i].Type) == "aws::autoscaling::launchconfiguration"
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
    "Policy Code": "PR-AWS-CFR-AS-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure EBS volumes have encrypted launch configurations",
    "Policy Description": "Amazon Elastic Block Store (EBS) volumes allow you to create encrypted launch configurations when creating EC2 instances and auto scaling. When the entire EBS volume is encrypted, data stored at rest on the volume, disk I/O, snapshots created from the volume, and data in-transit between EBS and EC2 are all encrypted.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-launchconfig-blockdev-template.html#cfn-as-launchconfig-blockdev-template-encrypted"
}

#
# PR-AWS-CFR-AS-002
#

default as_elb_health_check = null

aws_attribute_absence["as_elb_health_check"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::autoscaling::autoscalinggroup"
    resource.Properties.LoadBalancerNames
    not resource.Properties.HealthCheckType
}

source_path[{"as_elb_health_check": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::autoscaling::autoscalinggroup"
    resource.Properties.LoadBalancerNames
    not resource.Properties.HealthCheckType
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "HealthCheckType"]
        ],
    }
}

aws_issue["as_elb_health_check"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::autoscaling::autoscalinggroup"
    resource.Properties.LoadBalancerNames
    lower(resource.Properties.HealthCheckType) != "elb"
}

source_path[{"as_elb_health_check": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::autoscaling::autoscalinggroup"
    resource.Properties.LoadBalancerNames
    lower(resource.Properties.HealthCheckType) != "elb"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "HealthCheckType"]
        ],
    }
}

aws_attribute_absence["as_elb_health_check"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::autoscaling::autoscalinggroup"
    resource.Properties.TargetGroupARNs
    resource.Properties.HealthCheckType
}

source_path[{"as_elb_health_check": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::autoscaling::autoscalinggroup"
    resource.Properties.TargetGroupARNs
    resource.Properties.HealthCheckType
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "HealthCheckType"]
        ],
    }
}

aws_issue["as_elb_health_check"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::autoscaling::autoscalinggroup"
    resource.Properties.TargetGroupARNs
    lower(resource.Properties.HealthCheckType) != "elb"
}

source_path[{"as_elb_health_check": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::autoscaling::autoscalinggroup"
    resource.Properties.TargetGroupARNs
    lower(resource.Properties.HealthCheckType) != "elb"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "HealthCheckType"]
        ],
    }
}

as_elb_health_check {
    lower(input.Resources[i].Type) == "aws::autoscaling::autoscalinggroup"
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
    "Policy Code": "PR-AWS-CFR-AS-002",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure auto scaling groups associated with a load balancer use elastic load balancing health checks",
    "Policy Description": "If you configure an Auto Scaling group to use load balancer (ELB) health checks, it considers the instance unhealthy if it fails either the EC2 status checks or the load balancer health checks",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#cfn-as-group-healthchecktype"
}

#
# PR-AWS-CFR-CFR-001
#

default cf_sns = null

aws_issue["cf_sns"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudformation::stack"
    not resource.Properties.NotificationARNs
}

source_path[{"cf_sns": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudformation::stack"
    not resource.Properties.NotificationARNs
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "NotificationARNs"]
        ],
    }
}

aws_issue["cf_sns"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudformation::stack"
    count(resource.Properties.NotificationARNs) == 0
}

source_path[{"cf_sns": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudformation::stack"
    count(resource.Properties.NotificationARNs) == 0
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "NotificationARNs"]
        ],
    }
}

cf_sns {
    lower(input.Resources[i].Type) == "aws::cloudformation::stack"
    not aws_issue["cf_sns"]
}

cf_sns = false {
    aws_issue["cf_sns"]
}

cf_sns_err = "AWS CloudFormation stack configured without SNS topic" {
    aws_issue["cf_sns"]
}

cf_sns_metadata := {
    "Policy Code": "PR-AWS-CFR-CFR-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS CloudFormation stack configured without SNS topic",
    "Policy Description": "This policy identifies CloudFormation stacks which are configured without SNS topic. It is recommended to configure Simple Notification Service (SNS) topic to be notified of CloudFormation stack status and changes.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-stack.html"
}


#
# PR-AWS-CFR-CFG-001
#

default config_all_resource = null

aws_issue["config_all_resource"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::config::configurationrecorder"
    not resource.Properties.RecordingGroup
}

source_path[{"config_all_resource": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::config::configurationrecorder"
    not resource.Properties.RecordingGroup
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "RecordingGroup"]
        ],
    }
}

aws_issue["config_all_resource"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::config::configurationrecorder"
    resource.Properties.RecordingGroup
    lower(resource.Properties.RecordingGroup.AllSupported) == "false"
}

source_path[{"config_all_resource": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::config::configurationrecorder"
    resource.Properties.RecordingGroup
    lower(resource.Properties.RecordingGroup.AllSupported) == "false"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "RecordingGroup", "AllSupported"]
        ],
    }
}

aws_issue["config_all_resource"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::config::configurationrecorder"
    resource.Properties.RecordingGroup
    lower(resource.Properties.RecordingGroup.IncludeGlobalResourceTypes) == "false"
}

source_path[{"config_all_resource": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::config::configurationrecorder"
    resource.Properties.RecordingGroup
    lower(resource.Properties.RecordingGroup.IncludeGlobalResourceTypes) == "false"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "RecordingGroup", "IncludeGlobalResourceTypes"]
        ],
    }
}

aws_bool_issue["config_all_resource"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::config::configurationrecorder"
    resource.Properties.RecordingGroup
    not resource.Properties.RecordingGroup.AllSupported
}

source_path[{"config_all_resource": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::config::configurationrecorder"
    resource.Properties.RecordingGroup
    not resource.Properties.RecordingGroup.AllSupported
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "RecordingGroup", "AllSupported"]
        ],
    }
}

aws_bool_issue["config_all_resource"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::config::configurationrecorder"
    resource.Properties.RecordingGroup
    not resource.Properties.RecordingGroup.IncludeGlobalResourceTypes
}

source_path[{"config_all_resource": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::config::configurationrecorder"
    resource.Properties.RecordingGroup
    not resource.Properties.RecordingGroup.IncludeGlobalResourceTypes
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "RecordingGroup", "IncludeGlobalResourceTypes"]
        ],
    }
}

config_all_resource {
    lower(input.Resources[i].Type) == "aws::config::configurationrecorder"
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
    "Policy Code": "PR-AWS-CFR-CFG-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Config must record all possible resources",
    "Policy Description": "This policy identifies resources for which AWS Config recording is enabled but recording for all possible resources are disabled. AWS Config provides an inventory of your AWS resources and a history of configuration changes to these resources. You can use AWS Config to define rules that evaluate these configurations for compliance. Hence, it is important to enable this feature.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-config-configurationrecorder.html"
}


#
# PR-AWS-CFR-CFG-002
#

default aws_config_configuration_aggregator = null

aws_issue["aws_config_configuration_aggregator"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::config::configurationaggregator"
    not resource.Properties.AccountAggregationSources.AllAwsRegions
}

source_path[{"aws_config_configuration_aggregator": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::config::configurationaggregator"
    not resource.Properties.AccountAggregationSources.AllAwsRegions
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "AccountAggregationSources", "AllAwsRegions"]
        ],
    }
}

aws_issue["aws_config_configuration_aggregator"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::config::configurationaggregator"
    lower(resource.Properties.AccountAggregationSources.AllAwsRegions) != "true"
}

source_path[{"aws_config_configuration_aggregator": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::config::configurationaggregator"
    lower(resource.Properties.AccountAggregationSources.AllAwsRegions) != "true"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "AccountAggregationSources", "AllAwsRegions"]
        ],
    }
}

aws_config_configuration_aggregator {
    lower(input.Resources[i].Type) == "aws::config::configurationaggregator"
    not aws_issue["aws_config_configuration_aggregator"]
}

aws_config_configuration_aggregator = false {
    aws_issue["aws_config_configuration_aggregator"]
}

aws_config_configuration_aggregator_err = "Ensure AWS config is enabled in all regions" {
    aws_issue["aws_config_configuration_aggregator"]
}

aws_config_configuration_aggregator_metadata := {
    "Policy Code": "PR-AWS-CFR-CFG-002",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure AWS config is enabled in all regions",
    "Policy Description": "AWS Config is a web service that performs the configuration management of supported AWS resources within your account and delivers log files to you.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-config-configurationaggregator-accountaggregationsource.html#cfn-config-configurationaggregator-accountaggregationsource-allawsregions"
}


#
# PR-AWS-CFR-KNS-001
#
default kinesis_encryption = null

aws_issue["kinesis_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::kinesis::stream"
    not resource.Properties.StreamEncryption
}

source_path[{"kinesis_encryption": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::kinesis::stream"
    not resource.Properties.StreamEncryption
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "StreamEncryption"]
        ],
    }
}

aws_issue["kinesis_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::kinesis::stream"
    count(resource.Properties.StreamEncryption) == 0
}

source_path[{"kinesis_encryption": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::kinesis::stream"
    count(resource.Properties.StreamEncryption) == 0
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "StreamEncryption"]
        ],
    }
}

kinesis_encryption {
    lower(input.Resources[i].Type) == "aws::kinesis::stream"
    not aws_issue["kinesis_encryption"]
}

kinesis_encryption = false {
    aws_issue["kinesis_encryption"]
}

kinesis_encryption_err = "AWS Kinesis streams are not encrypted using Server Side Encryption" {
    aws_issue["kinesis_encryption"]
}

kinesis_encryption_metadata := {
    "Policy Code": "PR-AWS-CFR-KNS-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Kinesis streams are not encrypted using Server Side Encryption",
    "Policy Description": "This Policy identifies the AWS Kinesis streams which are not encrypted using Server Side Encryption. Server Side Encryption is used to encrypt your sensitive data before it is written to the Kinesis stream storage layer and decrypted after it is retrieved from storage.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-kinesis-stream.html#aws-resource-kinesis-stream--examples"
}

#
# PR-AWS-CFR-KNS-002
#

default kinesis_encryption_kms = null

aws_issue["kinesis_encryption_kms"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::kinesis::stream"
    not resource.Properties.StreamEncryption.EncryptionType
}

source_path[{"kinesis_encryption_kms": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::kinesis::stream"
    not resource.Properties.StreamEncryption.EncryptionType
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "StreamEncryption", "EncryptionType"]
        ],
    }
}

aws_issue["kinesis_encryption_kms"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::kinesis::stream"
    lower(resource.Properties.StreamEncryption.EncryptionType) != "kms"
}

source_path[{"kinesis_encryption_kms": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::kinesis::stream"
    lower(resource.Properties.StreamEncryption.EncryptionType) != "kms"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "StreamEncryption", "EncryptionType"]
        ],
    }
}

kinesis_encryption_kms {
    lower(input.Resources[i].Type) == "aws::kinesis::stream"
    not aws_issue["kinesis_encryption_kms"]
}

kinesis_encryption_kms = false {
    aws_issue["kinesis_encryption_kms"]
}

kinesis_encryption_kms_err = "AWS Kinesis streams encryption using default KMS keys instead of Customer's Managed Master Keys" {
    aws_issue["kinesis_encryption_kms"]
}

kinesis_encryption_kms_metadata := {
    "Policy Code": "PR-AWS-CFR-KNS-002",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Kinesis streams encryption using default KMS keys instead of Customer's Managed Master Keys",
    "Policy Description": "This policy identifies the AWS Kinesis streams which are encrypted with default KMS keys and not with Master Keys managed by Customer. It is a best practice to use customer managed Master Keys to encrypt your Amazon Kinesis streams data. It gives you full control over the encrypted data.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-kinesis-stream.html#aws-resource-kinesis-stream--examples"
}


#
# PR-AWS-CFR-MQ-001
#
default mq_publicly_accessible = null

aws_bool_issue["mq_publicly_accessible"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::amazonmq::broker"
    resource.Properties.PubliclyAccessible == true
}

source_path[{"mq_publicly_accessible": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::amazonmq::broker"
    resource.Properties.PubliclyAccessible == true
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "PubliclyAccessible"]
        ],
    }
}

aws_issue["mq_publicly_accessible"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::amazonmq::broker"
    lower(resource.Properties.PubliclyAccessible) == "true"
}

source_path[{"mq_publicly_accessible": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::amazonmq::broker"
    lower(resource.Properties.PubliclyAccessible) == "true"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "PubliclyAccessible"]
        ],
    }
}

mq_publicly_accessible {
    lower(input.Resources[i].Type) == "aws::amazonmq::broker"
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
    "Policy Code": "PR-AWS-CFR-MQ-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS MQ is publicly accessible",
    "Policy Description": "This policy identifies the AWS MQ brokers which are publicly accessible. It is advisable to use MQ brokers privately only from within your AWS Virtual Private Cloud (VPC). Ensure that the AWS MQ brokers provisioned in your AWS account are not publicly accessible from the Internet to avoid sensitive data exposure and minimize security risks.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-broker.html#cfn-amazonmq-broker-publiclyaccessible"
}


#
# PR-AWS-CFR-MQ-002
#
default mq_logging_enable = null

aws_issue["mq_logging_enable"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::amazonmq::broker"
    not resource.Properties.Logs
}

source_path[{"mq_logging_enable": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::amazonmq::broker"
    not resource.Properties.Logs
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "Logs"]
        ],
    }
}

aws_issue["mq_logging_enable"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::amazonmq::broker"
    count(resource.Properties.Logs) == 0
}

source_path[{"mq_logging_enable": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::amazonmq::broker"
    count(resource.Properties.Logs) == 0
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "Logs"]
        ],
    }
}

aws_issue["mq_logging_enable"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::amazonmq::broker"
    Logs := resource.Properties.Logs[j]
    not Logs.General
}

source_path[{"mq_logging_enable": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::amazonmq::broker"
    Logs := resource.Properties.Logs[j]
    not Logs.General
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "Logs", j, "General"]
        ],
    }
}

aws_issue["mq_logging_enable"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::amazonmq::broker"
    Logs := resource.Properties.Logs[j]
    lower(Logs.General) == "false"
}

source_path[{"mq_logging_enable": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::amazonmq::broker"
    Logs := resource.Properties.Logs[j]
    lower(Logs.General) == "false"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "Logs", j, "General"]
        ],
    }
}

mq_logging_enable {
    lower(input.Resources[i].Type) == "aws::amazonmq::broker"
    not aws_issue["mq_logging_enable"]
}

mq_logging_enable = false {
    aws_issue["mq_logging_enable"]
}


mq_logging_enable_err = "Ensure Amazon MQ Broker logging is enabled" {
    aws_issue["mq_logging_enable"]
}


mq_logging_enable_metadata := {
    "Policy Code": "PR-AWS-CFR-MQ-002",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure Amazon MQ Broker logging is enabled",
    "Policy Description": "Amazon MQ is integrated with CloudTrail and provides a record of the Amazon MQ calls made by a user, role, or AWS service. It supports logging both the request parameters and the responses for APIs as events in CloudTrail",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-broker.html#cfn-amazonmq-broker-publiclyaccessible"
}


#
# PR-AWS-CFR-R53-001
#

default route_healthcheck_disable = null

aws_issue["route_healthcheck_disable"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::route53::recordsetgroup"
    record_set := resource.Properties.RecordSets[j]
    lower(record_set.AliasTarget.EvaluateTargetHealth) == "false"
}

source_path[{"route_healthcheck_disable": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::route53::recordsetgroup"
    record_set := resource.Properties.RecordSets[j]
    lower(record_set.AliasTarget.EvaluateTargetHealth) == "false"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "RecordSets", j, "AliasTarget", "EvaluateTargetHealth"]
        ],
    }
}

aws_bool_issue["route_healthcheck_disable"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::route53::recordsetgroup"
    record_set := resource.Properties.RecordSets[j]
    not record_set.AliasTarget.EvaluateTargetHealth
}

source_path[{"route_healthcheck_disable": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::route53::recordsetgroup"
    record_set := resource.Properties.RecordSets[j]
    not record_set.AliasTarget.EvaluateTargetHealth
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "RecordSets", j, "AliasTarget", "EvaluateTargetHealth"]
        ],
    }
}

aws_issue["route_healthcheck_disable"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::route53::recordset"
    lower(resource.Properties.AliasTarget.EvaluateTargetHealth) == "false"
}

source_path[{"route_healthcheck_disable": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::route53::recordset"
    lower(resource.Properties.AliasTarget.EvaluateTargetHealth) == "false"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "AliasTarget", "EvaluateTargetHealth"]
        ],
    }
}

aws_bool_issue["route_healthcheck_disable"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::route53::recordset"
    not resource.Properties.AliasTarget.EvaluateTargetHealth
}


source_path[{"route_healthcheck_disable": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::route53::recordset"
    not resource.Properties.AliasTarget.EvaluateTargetHealth
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "AliasTarget", "EvaluateTargetHealth"]
        ],
    }
}

route_healthcheck_disable {
    lower(input.Resources[i].Type) == "aws::route53::recordsetgroup"
    not aws_issue["route_healthcheck_disable"]
    not aws_bool_issue["route_healthcheck_disable"]
}

route_healthcheck_disable {
    lower(input.Resources[i].Type) == "aws::route53::recordset"
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
    "Policy Code": "PR-AWS-CFR-R53-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure Route53 DNS evaluateTargetHealth is enabled",
    "Policy Description": "The EvaluateTargetHealth of Route53 is not enabled, an alias record can't inherits the health of the referenced AWS resource, such as an ELB load balancer or another record in the hosted zone.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html"
}

#
# PR-AWS-CFR-WAF-001
#

default waf_log4j_vulnerability = null

aws_issue["waf_log4j_vulnerability"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::wafv2::webacl"
    Rules := resource.Properties.Rules[_]
    lower(Rules.Statement.ManagedRuleGroupStatement.Name) == "awsmanagedrulesknownbadinputsruleset"
    ExcludedRules := Rules.Statement.ManagedRuleGroupStatement.ExcludedRules[_]
    lower(ExcludedRules.Name) == "log4jrce"

}

aws_issue["waf_log4j_vulnerability"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::wafv2::webacl"
    Rules := resource.Properties.Rules[_]
    not has_property(Rules.OverrideAction, "None")
}

waf_log4j_vulnerability {
    lower(input.Resources[i].Type) == "aws::wafv2::webacl"
    not aws_issue["waf_log4j_vulnerability"]
}

waf_log4j_vulnerability = false {
    aws_issue["waf_log4j_vulnerability"]
}

waf_log4j_vulnerability_err = "JMSAppender in Log4j 1.2 is vulnerable to deserialization of untrusted data when the attacker has write access to the Log4j configuration" {
    aws_issue["waf_log4j_vulnerability"]
}

waf_log4j_vulnerability_metadata := {
    "Policy Code": "PR-AWS-CFR-WAF-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "JMSAppender in Log4j 1.2 is vulnerable to deserialization of untrusted data when the attacker has write access to the Log4j configuration",
    "Policy Description": "Apache Log4j2 2.0-beta9 through 2.12.1 and 2.13.0 through 2.15.0 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-managedrulegroupstatement.html#cfn-wafv2-webacl-managedrulegroupstatement-name"
}
