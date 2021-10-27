package rule


#
# PR-AWS-TRF-CFR-001
#

default cf_sns = null

aws_issue["cf_sns"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudformation_stack"
    not resource.properties.notification_arns
}

aws_issue["cf_sns"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudformation_stack"
    count(resource.properties.notification_arns) == 0
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

aws_issue["config_all_resource"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_config_configuration_recorder"
    recording_group := resource.properties.recording_group[_]
    lower(recording_group.all_supported) == "false"
}

aws_issue["config_all_resource"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_config_configuration_recorder"
    recording_group := resource.properties.recording_group[_]
    lower(recording_group.include_global_resource_types) == "false"
}

aws_bool_issue["config_all_resource"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_config_configuration_recorder"
    recording_group := resource.properties.recording_group[_]
    not recording_group.all_supported
}

aws_bool_issue["config_all_resource"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_config_configuration_recorder"
    recording_group := resource.properties.recording_group[_]
    not recording_group.include_global_resource_types
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
# PR-AWS-TRF-KNS-001
#
default kinesis_encryption = null

aws_issue["kinesis_encryption"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_kinesis_stream"
    not resource.properties.encryption_type
}

aws_issue["kinesis_encryption"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_kinesis_stream"
    resource.properties.encryption_type == null
}

aws_issue["kinesis_encryption"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_kinesis_stream"
    count(resource.properties.encryption_type) == 0
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

aws_issue["kinesis_encryption_kms"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_kinesis_stream"
    resource.properties.encryption_type == null
}

aws_issue["kinesis_encryption_kms"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_kinesis_stream"
    lower(resource.properties.encryption_type) != "kms"
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

aws_issue["mq_publicly_accessible"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_mq_broker"
    lower(resource.properties.publicly_accessible) == "true"
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
# PR-AWS-TRF-R53-001
#

default route_healthcheck_disable = null

aws_issue["route_healthcheck_disable"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_route53_record"
    alias := resource.properties.alias[_]
    lower(alias.evaluate_target_health) == "false"
}

aws_bool_issue["route_healthcheck_disable"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_route53_record"
    alias := resource.properties.alias[_]
    not alias.evaluate_target_health
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
# PR-AWS-TRF-AS-001
#

default as_volume_encrypted = null

aws_issue["as_volume_encrypted"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_launch_configuration"
    count([c | resource.properties.ebs_block_device; c:=1]) == 0
}

aws_bool_issue["as_volume_encrypted"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_launch_configuration"
    ebs_block_device := resource.properties.ebs_block_device[_]
    not ebs_block_device.encrypted
}

aws_issue["as_volume_encrypted"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_launch_configuration"
    ebs_block_device := resource.properties.ebs_block_device[_]
    lower(ebs_block_device.encrypted) != "true"
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