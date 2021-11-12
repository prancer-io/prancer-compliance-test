package rule

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
# PR-AWS-TRF-AS-002
#

default as_elb_health_check = null

aws_issue["as_elb_health_check"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_autoscaling_group"
    resource.properties.load_balancers
    lower(resource.properties.health_check_type) != "elb"
}

source_path[{"as_elb_health_check": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_autoscaling_group"
    resource.properties.load_balancers
    lower(resource.properties.health_check_type) != "elb"
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "health_check_type"]
        ],
    }
}

aws_issue["as_elb_health_check"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_autoscaling_group"
    resource.properties.target_group_arns
    lower(resource.properties.health_check_type) != "elb"
}

source_path[{"as_elb_health_check": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_autoscaling_group"
    resource.properties.target_group_arns
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
}

as_elb_health_check = false {
    aws_issue["as_elb_health_check"]
}

as_elb_health_check_err = "Ensure auto scaling groups associated with a load balancer use elastic load balancing health checks" {
    aws_issue["as_elb_health_check"]
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

aws_issue["glue_security_config_disable"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_glue_security_configuration"
    not resource.properties.encryption_configuration
}

source_path[{"glue_security_config_disable": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_glue_security_configuration"
    not resource.properties.encryption_configuration
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "encryption_configuration"]
        ],
    }
}

aws_issue["glue_security_config_disable"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_glue_security_configuration"
    encryption_configuration := resource.properties.encryption_configuration[j]
    cloudwatch_encryption := encryption_configuration.cloudwatch_encryption[k]
    lower(cloudwatch_encryption.cloudwatch_encryption_mode) != "SSE-KMS"
}

source_path[{"glue_security_config_disable": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_glue_security_configuration"
    encryption_configuration := resource.properties.encryption_configuration[j]
    cloudwatch_encryption := encryption_configuration.cloudwatch_encryption[k]
    lower(cloudwatch_encryption.cloudwatch_encryption_mode) != "SSE-KMS"
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "encryption_configuration", j, "cloudwatch_encryption", k, "cloudwatch_encryption_mode"]
        ],
    }
}

aws_issue["glue_security_config_disable"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_glue_security_configuration"
    encryption_configuration := resource.properties.encryption_configuration[j]
    job_bookmarks_encryption := encryption_configuration.job_bookmarks_encryption[k]
    lower(job_bookmarks_encryption.job_bookmarks_encryption_mode) != "SSE-KMS"
}

source_path[{"glue_security_config_disable": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_glue_security_configuration"
    encryption_configuration := resource.properties.encryption_configuration[j]
    job_bookmarks_encryption := encryption_configuration.job_bookmarks_encryption[k]
    lower(job_bookmarks_encryption.job_bookmarks_encryption_mode) != "SSE-KMS"
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "encryption_configuration", j, "job_bookmarks_encryption", k, "job_bookmarks_encryption_mode"]
        ],
    }
}

aws_issue["glue_security_config_disable"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_glue_security_configuration"
    encryption_configuration := resource.properties.encryption_configuration[j]
    s3_encryption := encryption_configuration.s3_encryption[k]
    lower(s3_encryption.s3_encryption_mode) != "SSE-KMS"
}

source_path[{"glue_security_config_disable": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_glue_security_configuration"
    encryption_configuration := resource.properties.encryption_configuration[j]
    s3_encryption := encryption_configuration.s3_encryption[k]
    lower(s3_encryption.s3_encryption_mode) != "SSE-KMS"
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