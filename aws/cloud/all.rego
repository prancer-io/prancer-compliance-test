package rule

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