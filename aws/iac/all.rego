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
# PR-AWS-CFR-SM-002
#

default secret_manager_vpc_subnet_id = null

aws_issue["secret_manager_vpc_subnet_id"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::secretsmanager::rotationschedule"
    not resource.Properties.HostedRotationLambda.VpcSubnetIds
}

aws_issue["secret_manager_vpc_subnet_id"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::secretsmanager::rotationschedule"
    count(resource.Properties.HostedRotationLambda.VpcSubnetIds) == 0
}

secret_manager_vpc_subnet_id {
    lower(input.Resources[i].Type) == "aws::secretsmanager::rotationschedule"
    not aws_issue["secret_manager_vpc_subnet_id"]
}

secret_manager_vpc_subnet_id = false {
    aws_issue["secret_manager_vpc_subnet_id"]
}

secret_manager_vpc_subnet_id_err = "Ensure that SecretsManager RotationSchedule HostedRotationLambda attaches to a VPC Subnet IDs" {
    aws_issue["secret_manager_vpc_subnet_id"]
}

secret_manager_vpc_subnet_id_metadata := {
    "Policy Code": "PR-AWS-CFR-SM-002",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure that SecretsManager RotationSchedule HostedRotationLambda attaches to a VPC Subnet IDs",
    "Policy Description": "SecretsManager RotationSchedules should use Subnet IDs",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-secretsmanager-secret.html"
}


#
# PR-AWS-CFR-SM-003
#

default secret_manager_automatic_rotation = null

aws_issue["secret_manager_automatic_rotation"] {
    resource_1 := input.Resources[i]
    lower(resource_1.Type) == "aws::secretsmanager::secret"
    secret_id := resource_1.Properties.Name
    resource_2 := input.Resources[j]
    lower(resource_2.Type) == "aws::secretsmanager::rotationschedule"
    resource_2.Properties.SecretId.Ref != secret_id
}

aws_issue["secret_manager_automatic_rotation"] {
    resource_1 := input.Resources[i]
    lower(resource_1.Type) == "aws::secretsmanager::secret"
    secret_id := resource_1.Name
    resource_2 := input.Resources[j]
    lower(resource_2.Type) == "aws::secretsmanager::rotationschedule"
    resource_2.Properties.SecretId.Ref != secret_id
}

secret_manager_automatic_rotation {
    lower(input.Resources[i].Type) == "aws::secretsmanager::rotationschedule"
    not aws_issue["secret_manager_automatic_rotation"]
}

secret_manager_automatic_rotation = false {
    aws_issue["secret_manager_automatic_rotation"]
}

secret_manager_automatic_rotation_err = "Ensure AWS Secrets Manager automatic rotation is enabled." {
    aws_issue["secret_manager_automatic_rotation"]
}

secret_manager_automatic_rotation_metadata := {
    "Policy Code": "PR-AWS-CFR-SM-003",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure AWS Secrets Manager automatic rotation is enabled.",
    "Policy Description": "Rotation is the process of periodically updating a secret. When you rotate a secret, you update the credentials in both the secret and the database or service. This control checks if automatic rotation for secrets is enabled in the secrets manager configuration.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-secretsmanager-rotationschedule.html"
}


#
# PR-AWS-CFR-SM-004
#

default secret_manager_rotation_period = null

aws_issue["secret_manager_rotation_period"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::secretsmanager::rotationschedule"
    not resource.Properties.RotationRules.AutomaticallyAfterDays
}


aws_issue["secret_manager_rotation_period"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::secretsmanager::rotationschedule"
    to_number(resource.Properties.RotationRules.AutomaticallyAfterDays) > 30
}

secret_manager_rotation_period {
    lower(input.Resources[i].Type) == "aws::secretsmanager::rotationschedule"
    not aws_issue["secret_manager_rotation_period"]
}

secret_manager_rotation_period = false {
    aws_issue["secret_manager_rotation_period"]
}

secret_manager_rotation_period_err = "Ensure AWS secret rotation period is per the GS standard (Ex: 30 days)." {
    aws_issue["secret_manager_rotation_period"]
}

secret_manager_rotation_period_metadata := {
    "Policy Code": "PR-AWS-CFR-SM-004",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure AWS secret rotation period is per the GS standard (Ex: 30 days).",
    "Policy Description": "It checks if the rotation policy follow GS standards. Secret rotation period should be less than 30 days.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-secretsmanager-rotationschedule-rotationrules.html#cfn-secretsmanager-rotationschedule-rotationrules-automaticallyafterdays"
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
# PR-AWS-CFR-WS-002
#

default workspace_root_volume_encrypt = null

aws_issue["workspace_root_volume_encrypt"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::workspaces::workspace"
    not resource.Properties.RootVolumeEncryptionEnabled
}

aws_issue["workspace_root_volume_encrypt"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::workspaces::workspace"
    lower(resource.Properties.RootVolumeEncryptionEnabled) == "false"
}

workspace_root_volume_encrypt {
    lower(input.Resources[i].Type) == "aws::workspaces::workspace"
    not aws_issue["workspace_root_volume_encrypt"]
}

workspace_root_volume_encrypt = false {
    aws_issue["workspace_root_volume_encrypt"]
}

workspace_root_volume_encrypt_err = "Ensure that Workspace root volumes is encrypted." {
    aws_issue["workspace_root_volume_encrypt"]
}

workspace_root_volume_encrypt_metadata := {
    "Policy Code": "PR-AWS-CFR-WS-002",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure that Workspace root volumes is encrypted.",
    "Policy Description": "It checks if encryption is enabled for workspace root volumes.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-workspaces-workspace.html#cfn-workspaces-workspace-rootvolumeencryptionenabled"
}


#
# PR-AWS-CFR-WS-003
#

default workspace_directory_type = null

aws_issue["workspace_directory_type"] {
    resource_1 := input.Resources[i]
    lower(resource_1.Type) == "aws::directoryservice::simplead"
    directory_id := resource_1.Properties.Name
    resource_2 := input.Resources[j]
    lower(resource_2.Type) == "aws::workspaces::workspace"
    resource_2.Properties.DirectoryId.Ref == directory_id
}

aws_issue["workspace_directory_type"] {
    resource_1 := input.Resources[i]
    lower(resource_1.Type) == "aws::directoryservice::simplead"
    directory_id := resource_1.Name
    resource_2 := input.Resources[j]
    lower(resource_2.Type) == "aws::workspaces::workspace"
    resource_2.Properties.DirectoryId.Ref == directory_id
}

workspace_directory_type {
    lower(input.Resources[i].Type) == "aws::workspaces::workspace"
    not aws_issue["workspace_directory_type"]
}

workspace_directory_type = false {
    aws_issue["workspace_directory_type"]
}

workspace_directory_type_err = "Ensure AWS WorkSpaces do not use directory type Simple AD." {
    aws_issue["workspace_directory_type"]
}

workspace_directory_type_metadata := {
    "Policy Code": "PR-AWS-CFR-WS-003",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure AWS WorkSpaces do not use directory type Simple AD.",
    "Policy Description": "It checks if Simple AD is used for workspace users. MS Active Directory is approved by GS to be used.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-workspaces-workspace.html#cfn-workspaces-workspace-directoryid"
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
    lower(resource.Properties.EncryptionConfiguration.CloudWatchEncryption.CloudWatchEncryptionMode) != "sse-kms"
}

source_path[{"glue_security_config": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::glue::securityconfiguration"
    lower(resource.Properties.EncryptionConfiguration.CloudWatchEncryption.CloudWatchEncryptionMode) != "sse-kms"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "EncryptionConfiguration", "CloudWatchEncryption", "CloudWatchEncryptionMode"]
        ],
    }
}

aws_issue["glue_security_config"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::glue::securityconfiguration"
    lower(resource.Properties.EncryptionConfiguration.JobBookmarksEncryption.JobBookmarksEncryptionMode) != "sse-kms"
}

source_path[{"glue_security_config": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::glue::securityconfiguration"
    lower(resource.Properties.EncryptionConfiguration.JobBookmarksEncryption.JobBookmarksEncryptionMode) != "sse-kms"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "EncryptionConfiguration", "JobBookmarksEncryption", "JobBookmarksEncryptionMode"]
        ],
    }
}

aws_issue["glue_security_config"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::glue::securityconfiguration"
    lower(resource.Properties.EncryptionConfiguration.S3Encryptions.S3EncryptionMode) != "sse-kms"
}

source_path[{"glue_security_config": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::glue::securityconfiguration"
    lower(resource.Properties.EncryptionConfiguration.S3Encryptions.S3EncryptionMode) != "sse-kms"
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
# PR-AWS-CFR-GLUE-003
#

default glue_encrypt_data_at_rest = null

aws_issue["glue_encrypt_data_at_rest"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::glue::securityconfiguration"
    lower(resource.Properties.EncryptionConfiguration.CloudWatchEncryption.CloudWatchEncryptionMode) == "disabled"
}

aws_issue["glue_encrypt_data_at_rest"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::glue::securityconfiguration"
    not resource.Properties.EncryptionConfiguration.CloudWatchEncryption.CloudWatchEncryptionMode
}

aws_issue["glue_encrypt_data_at_rest"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::glue::securityconfiguration"
    lower(resource.Properties.EncryptionConfiguration.JobBookmarksEncryption.JobBookmarksEncryptionMode) == "disabled"
}

aws_issue["glue_encrypt_data_at_rest"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::glue::securityconfiguration"
    not resource.Properties.EncryptionConfiguration.JobBookmarksEncryption.JobBookmarksEncryptionMode
}

aws_issue["glue_encrypt_data_at_rest"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::glue::securityconfiguration"
    lower(resource.Properties.EncryptionConfiguration.S3Encryptions.S3EncryptionMode) == "disabled"
}

aws_issue["glue_encrypt_data_at_rest"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::glue::securityconfiguration"
    not resource.Properties.EncryptionConfiguration.S3Encryptions.S3EncryptionMode
}

glue_encrypt_data_at_rest {
    lower(input.Resources[i].Type) == "aws::glue::securityconfiguration"
    not aws_issue["glue_encrypt_data_at_rest"]
}

glue_encrypt_data_at_rest = false {
    aws_issue["glue_encrypt_data_at_rest"]
}

glue_encrypt_data_at_rest_err = "Ensure AWS Glue encrypt data at rest" {
    aws_issue["glue_encrypt_data_at_rest"]
}

glue_encrypt_data_at_rest_metadata := {
    "Policy Code": "PR-AWS-CFR-GLUE-003",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure AWS Glue encrypt data at rest",
    "Policy Description": "It is to check that AWS Glue encryption at rest is enabled.",
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
    count(resource.Properties.LoadBalancerNames) != 0
    not resource.Properties.HealthCheckType
}

source_path[{"as_elb_health_check": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::autoscaling::autoscalinggroup"
    count(resource.Properties.LoadBalancerNames) != 0
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
    count(resource.Properties.LoadBalancerNames) != 0
    lower(resource.Properties.HealthCheckType) != "elb"
}

source_path[{"as_elb_health_check": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::autoscaling::autoscalinggroup"
    count(resource.Properties.LoadBalancerNames) != 0
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
    count(resource.Properties.TargetGroupARNs) != 0
    resource.Properties.HealthCheckType
}

source_path[{"as_elb_health_check": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::autoscaling::autoscalinggroup"
    count(resource.Properties.TargetGroupARNs) != 0
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
    count(resource.Properties.TargetGroupARNs) != 0
    lower(resource.Properties.HealthCheckType) != "elb"
}

source_path[{"as_elb_health_check": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::autoscaling::autoscalinggroup"
    count(resource.Properties.TargetGroupARNs) != 0
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
# PR-AWS-CFR-AS-003
#

default as_http_token = null

aws_issue["as_http_token"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::autoscaling::launchconfiguration"
    lower(resource.Properties.MetadataOptions.HttpTokens) != "required"
}

aws_attribute_absence["as_http_token"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::autoscaling::launchconfiguration"
    not resource.Properties.MetadataOptions.HttpTokens
}

as_http_token {
    lower(input.Resources[i].Type) == "aws::autoscaling::launchconfiguration"
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
    "Policy Code": "PR-AWS-CFR-AS-003",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure EC2 Auto Scaling Group does not launch IMDSv1",
    "Policy Description": "This control checks if EC2 instances use IMDSv1 instead of IMDSv2, this also applies to instances created in the ASG.IMDSv1 is vulnerable to Server Side Request Forgery (SSRF) vulnerabilities in web applications running on EC2, open Website Application Firewalls, open reverse proxies, and open layer 3 firewalls and NATs. IMDSv2 uses session-oriented requests every request is now protected by session authentication.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-launchconfiguration-metadataoptions.html#cfn-autoscaling-launchconfiguration-metadataoptions-httptokens"
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
# PR-AWS-CFR-CFG-004
#

default config_includes_global_resources = null

aws_issue["config_includes_global_resources"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::config::configurationrecorder"
    resource.Properties.RecordingGroup.IncludeGlobalResourceTypes == available_false_choices[_]
}

aws_issue["config_includes_global_resources"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::config::configurationrecorder"
    not resource.Properties.RecordingGroup.IncludeGlobalResourceTypes
}

config_includes_global_resources {
    lower(input.Resources[i].Type) == "aws::config::configurationrecorder"
    not aws_issue["config_includes_global_resources"]
}

config_includes_global_resources = false {
    aws_issue["config_includes_global_resources"]
}

config_includes_global_resources_err = "Ensure AWS Config includes global resources types (IAM)." {
    aws_issue["config_includes_global_resources"]
}

config_includes_global_resources_metadata := {
    "Policy Code": "PR-AWS-CFR-CFG-004",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure AWS Config includes global resources types (IAM).",
    "Policy Description": "It checks that global resource types are included in AWS Config.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-config-configurationrecorder.html#aws-resource-config-configurationrecorder--examples"
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
# PR-AWS-CFR-MQ-003
#

default mq_activemq_approved_engine_version = null

aws_issue["mq_activemq_approved_engine_version"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::amazonmq::broker"
    lower(resource.Properties.EngineType) == "activemq"
    not startswith(resource.Properties.EngineVersion, "5.16")
}

mq_activemq_approved_engine_version {
    lower(input.Resources[i].Type) == "aws::amazonmq::broker"
    not aws_issue["mq_activemq_approved_engine_version"]
}

mq_activemq_approved_engine_version = false {
    aws_issue["mq_activemq_approved_engine_version"]
}


mq_activemq_approved_engine_version_err = "Ensure ActiveMQ engine version is approved by GS." {
    aws_issue["mq_activemq_approved_engine_version"]
}


mq_activemq_approved_engine_version_metadata := {
    "Policy Code": "PR-AWS-CFR-MQ-003",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure ActiveMQ engine version is approved by GS.",
    "Policy Description": "It is used to check only firm approved version of ActiveMQ is being used.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-broker.html#aws-resource-amazonmq-broker--examples"
}


#
# PR-AWS-CFR-MQ-004
#

default mq_rabbitmq_approved_engine_version = null

aws_issue["mq_rabbitmq_approved_engine_version"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::amazonmq::broker"
    lower(resource.Properties.EngineType) == "rabbitmq"
    not startswith(resource.Properties.EngineVersion, "3.8")
}

mq_rabbitmq_approved_engine_version {
    lower(input.Resources[i].Type) == "aws::amazonmq::broker"
    not aws_issue["mq_rabbitmq_approved_engine_version"]
}

mq_rabbitmq_approved_engine_version = false {
    aws_issue["mq_rabbitmq_approved_engine_version"]
}


mq_rabbitmq_approved_engine_version_err = "Ensure RabbitMQ engine version is approved by GS." {
    aws_issue["mq_rabbitmq_approved_engine_version"]
}


mq_rabbitmq_approved_engine_version_metadata := {
    "Policy Code": "PR-AWS-CFR-MQ-004",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure RabbitMQ engine version is approved by GS.",
    "Policy Description": "It is used to check only firm approved version of RabbitMQ is being used.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-broker.html#aws-resource-amazonmq-broker--examples"
}


#
# PR-AWS-CFR-MQ-005
#

default audit_logs_published_to_cloudWatch = null

aws_issue["audit_logs_published_to_cloudWatch"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::amazonmq::broker"
    lower(resource.Properties.EngineType) == "activemq"
    not resource.Properties.Logs
}

aws_issue["audit_logs_published_to_cloudWatch"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::amazonmq::broker"
    lower(resource.Properties.EngineType) == "activemq"
    log := resource.Properties.Logs[_]
    log.Audit == false
}

aws_issue["audit_logs_published_to_cloudWatch"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::amazonmq::broker"
    lower(resource.Properties.EngineType) == "activemq"
    log := resource.Properties.Logs[_]
    not log.Audit
}

audit_logs_published_to_cloudWatch {
    lower(input.Resources[i].Type) == "aws::amazonmq::broker"
    not aws_issue["audit_logs_published_to_cloudWatch"]
}

audit_logs_published_to_cloudWatch = false {
    aws_issue["audit_logs_published_to_cloudWatch"]
}


audit_logs_published_to_cloudWatch_err = "Ensure General and Audit logs are published to CloudWatch." {
    aws_issue["audit_logs_published_to_cloudWatch"]
}


audit_logs_published_to_cloudWatch_metadata := {
    "Policy Code": "PR-AWS-CFR-MQ-005",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure General and Audit logs are published to CloudWatch.",
    "Policy Description": "It is used to check that Amazon MQ is configured to push logs to CloudWatch in order to enhance troubleshooting in case of issues. It does not apply to RabbitMQ brokers.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-broker.html#aws-resource-amazonmq-broker--examples"
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
# PR-AWS-CFR-R53-002
#

default route_recordset_approved_type = null

approved_record_types := [
	"a",
	"cname",
]

aws_issue["route_recordset_approved_type"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::route53::recordset"
    count([c | lower(resource.Properties.Type) == approved_record_types[_]; c:=1 ]) == 0
}

route_recordset_approved_type {
    lower(input.Resources[i].Type) == "aws::route53::recordset"
    not aws_issue["route_recordset_approved_type"]
}

route_recordset_approved_type = false {
    aws_issue["route_recordset_approved_type"]
}

route_recordset_approved_type_err = "Ensure that the Route53 RecordSet Type is A or CNAME." {
    aws_issue["route_recordset_approved_type"]
}

route_recordset_approved_type_metadata := {
    "Policy Code": "PR-AWS-CFR-R53-002",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure that the Route53 RecordSet Type is A or CNAME.",
    "Policy Description": "Ensure that the Route53 RecordSet Type is A or CNAME.",
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



#
# PR-AWS-CFR-INS-001
#

default ins_package = null

aws_issue["ins_package"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::inspector::assessmenttemplate"
    count([c | lower(resource.Properties.RulesPackageArns[_]) == lower(rules_packages[_]); c:=1]) == 0
}

aws_issue["ins_package"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::inspector::assessmenttemplate"
    count(resource.Properties.RulesPackageArns) == 0
}

aws_issue["ins_package"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::inspector::assessmenttemplate"
    not resource.Properties.RulesPackageArns
}

ins_package {
    lower(input.Resources[i].Type) == "aws::inspector::assessmenttemplate"
    not aws_issue["ins_package"]
}

ins_package = false {
    aws_issue["ins_package"]
}

ins_package_err = "Enable AWS Inspector to detect Vulnerability" {
    aws_issue["ins_package"]
}

ins_package_metadata := {
    "Policy Code": "PR-AWS-CFR-INS-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud Formation",
    "Policy Title": "Enable AWS Inspector to detect Vulnerability",
    "Policy Description": "Enable AWS Inspector to detect Vulnerability",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-inspector-assessmenttemplate.html"
}



#
# PR-AWS-CFR-CW-001
#

default cw_alarm_account_id = null

aws_issue["cw_alarm_account_id"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudwatch::alarm"
    Metrics := resource.Properties.Metrics[_]
    not Metrics.AccountId
}

aws_issue["cw_alarm_account_id"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudwatch::alarm"
    Metrics := resource.Properties.Metrics[_]
    to_number(Metrics.AccountId) > 999999999999
}

aws_issue["cw_alarm_account_id"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudwatch::alarm"
    Metrics := resource.Properties.Metrics[_]
    to_number(Metrics.AccountId) <= 99999999999
}

cw_alarm_account_id {
    lower(input.Resources[i].Type) == "aws::cloudwatch::alarm"
    not aws_issue["cw_alarm_account_id"]
}

cw_alarm_account_id = false {
    aws_issue["cw_alarm_account_id"]
}

cw_alarm_account_id_err = "Ensure CloudWatch Alarm Metrics AccountId is valid" {
    aws_issue["cw_alarm_account_id"]
}

cw_alarm_account_id_metadata := {
    "Policy Code": "PR-AWS-CFR-CW-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud Formation",
    "Policy Title": "Ensure CloudWatch Alarm Metrics AccountId is valid",
    "Policy Description": "Ensure CloudWatch Alarm Metrics AccountId is valid",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudwatch-alarm-metricdataquery.html"
}


#
# PR-AWS-CFR-SC-001
#

default synthetics_artifact_s3 = null

aws_issue["synthetics_artifact_s3"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::synthetics::canary"
    not resource.Properties.ArtifactS3Location
}

aws_issue["synthetics_artifact_s3"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::synthetics::canary"
    count(resource.Properties.ArtifactS3Location) == 0
}

synthetics_artifact_s3 {
    lower(input.Resources[i].Type) == "aws::synthetics::canary"
    not aws_issue["synthetics_artifact_s3"]
}

synthetics_artifact_s3 = false {
    aws_issue["synthetics_artifact_s3"]
}

synthetics_artifact_s3_err = "Ensure Synthetic canary has defined ArtifactS3Locaton" {
    aws_issue["synthetics_artifact_s3"]
}

synthetics_artifact_s3_metadata := {
    "Policy Code": "PR-AWS-CFR-SC-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure Synthetic canary has defined ArtifactS3Locaton",
    "Policy Description": "Ensure Synthetic canary has defined ArtifactS3Locaton",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-secretsmanager-secret.html"
}


#
# PR-AWS-CFR-SC-002
#

default synthetics_vpc_config = null

aws_issue["synthetics_vpc_config"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::synthetics::canary"
    not resource.Properties.VPCConfig.VpcId
}

aws_issue["synthetics_vpc_config"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::synthetics::canary"
    count(resource.Properties.VPCConfig.VpcId) == 0
}

synthetics_vpc_config {
    lower(input.Resources[i].Type) == "aws::synthetics::canary"
    not aws_issue["synthetics_vpc_config"]
}

synthetics_vpc_config = false {
    aws_issue["synthetics_vpc_config"]
}

synthetics_vpc_config_err = "Ensure Synthetics Canary is attached to the Shared VPC." {
    aws_issue["synthetics_vpc_config"]
}

synthetics_vpc_config_metadata := {
    "Policy Code": "PR-AWS-CFR-SC-002",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure Synthetics Canary is attached to the Shared VPC.",
    "Policy Description": "Ensure Synthetics Canary is attached to the Shared VPC.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-secretsmanager-secret.html"
}


#
# PR-AWS-CFR-SC-003
#

default synthetics_security_group = null

aws_issue["synthetics_security_group"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::synthetics::canary"
    not resource.Properties.VPCConfig.SecurityGroupIds
}

aws_issue["synthetics_security_group"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::synthetics::canary"
    count(resource.Properties.VPCConfig.SecurityGroupIds) == 0
}

synthetics_security_group {
    lower(input.Resources[i].Type) == "aws::synthetics::canary"
    not aws_issue["synthetics_security_group"]
}

synthetics_security_group = false {
    aws_issue["synthetics_security_group"]
}

synthetics_security_group_err = "Ensure Synthetics Canary VPCConfig Security Groups are attached to VPC Config" {
    aws_issue["synthetics_security_group"]
}

synthetics_security_group_metadata := {
    "Policy Code": "PR-AWS-CFR-SC-003",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure Synthetics Canary VPCConfig Security Groups are attached to VPC Config",
    "Policy Description": "Ensure Synthetics Canary VPCConfig Security Groups are attached to VPC Config",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-secretsmanager-secret.html"
}

#
# PR-AWS-CFR-APS-001
#

default appsync_not_configured_with_firewall_v2 = null

aws_issue["appsync_not_configured_with_firewall_v2"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::appsync::graphqlapi"
    count([c | 
    	contains(lower(input.Resources[a].Properties.ResourceArn.Ref), lower(resource.Name)); 
        lower(input.Resources[a].Type) == "aws::wafregional::webaclassociation";
		input.Resources[a].Properties.WebACLId;
        c:=1 
    ]) == 0
}

appsync_not_configured_with_firewall_v2 {
    lower(input.Resources[i].Type) == "aws::appsync::graphqlapi"
    not aws_issue["appsync_not_configured_with_firewall_v2"]
}

appsync_not_configured_with_firewall_v2 = false {
    aws_issue["appsync_not_configured_with_firewall_v2"]
}

appsync_not_configured_with_firewall_v2_err = "Ensure AppSync is configured with AWS Web Application Firewall v2." {
    aws_issue["appsync_not_configured_with_firewall_v2"]
}

appsync_not_configured_with_firewall_v2_metadata := {
    "Policy Code": "PR-AWS-CFR-APS-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud Formation",
    "Policy Title": "Ensure AppSync is configured with AWS Web Application Firewall v2.",
    "Policy Description": "Enable the AWS WAF service on AppSync to protect against application layer attacks. To block malicious requests to your AppSync, define the block criteria in the WAF web access control list (web ACL).",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appsync-graphqlapi.html#aws-resource-appsync-graphqlapi--examples"
}