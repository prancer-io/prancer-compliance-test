package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html
# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-rds-database-instance.html

#
# PR-AWS-0119-TRF
#

default rds_cluster_encrypt = null

aws_issue["rds_cluster_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_rds_cluster"
    lower(resource.properties.storage_encrypted) == "false"
}

aws_bool_issue["rds_cluster_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_rds_cluster"
    not resource.properties.storage_encrypted
}

rds_cluster_encrypt {
    lower(input.resources[_].type) == "aws_rds_cluster"
    not aws_issue["rds_cluster_encrypt"]
    not aws_bool_issue["rds_cluster_encrypt"]
}

rds_cluster_encrypt = false {
    aws_issue["rds_cluster_encrypt"]
}

rds_cluster_encrypt = false {
    aws_bool_issue["rds_cluster_encrypt"]
}

rds_cluster_encrypt_err = "AWS RDS DB cluster encryption is disabled" {
    aws_issue["rds_cluster_encrypt"]
} else = "AWS RDS DB cluster encryption is disabled" {
    aws_bool_issue["rds_cluster_encrypt"]
}

rds_cluster_encrypt_metadata := {
    "Policy Code": "PR-AWS-0119-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS RDS DB cluster encryption is disabled",
    "Policy Description": "This policy identifies RDS DB clusters for which encryption is disabled. Amazon Aurora encrypted DB clusters provide an additional layer of data protection by securing your data from unauthorized access to the underlying storage. You can use Amazon Aurora encryption to increase data protection of your applications deployed in the cloud, and to fulfill compliance requirements for data-at-rest encryption.</br> NOTE: This policy is applicable only for Aurora DB clusters.</br> https://docs.aws.amazon.com/cli/latest/reference/rds/describe-db-clusters.html",
    "Resource Type": "aws_db_instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html"
}

#
# PR-AWS-0121-TRF
#

default rds_public = null

aws_bool_issue["rds_public"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_db_instance"
    resource.properties.publicly_accessible == true
}

aws_issue["rds_public"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_db_instance"
    lower(resource.properties.publicly_accessible) == "true"
}


rds_public {
    lower(input.resources[_].type) == "aws_db_instance"
    not aws_issue["rds_public"]
    not aws_bool_issue["rds_public"]
}

rds_public = false {
    aws_issue["rds_public"]
}

rds_public = false {
    aws_bool_issue["rds_public"]
}

rds_public_err = "AWS RDS database instance is publicly accessible" {
    aws_issue["rds_public"]
} else = "AWS RDS database instance is publicly accessible" {
    aws_bool_issue["rds_public"]
}

rds_public_metadata := {
    "Policy Code": "PR-AWS-0121-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS RDS database instance is publicly accessible",
    "Policy Description": "This policy identifies RDS database instances which are publicly accessible.DB instances should not be publicly accessible to protect the integrety of data.Public accessibility of DB instances can be modified by turning on or off the Public accessibility parameter.",
    "Resource Type": "aws_db_instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html"
}

#
# PR-AWS-0122-TRF
#

default rds_encrypt_key = null

aws_issue["rds_encrypt_key"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_db_instance"
    not resource.properties.kms_key_id
}

aws_issue["rds_encrypt_key"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_db_instance"
    count(resource.properties.kms_key_id) == 0
}

rds_encrypt_key {
    lower(input.resources[i].type) == "aws_db_instance"
    not aws_issue["rds_encrypt_key"]
}

rds_encrypt_key = false {
    aws_issue["rds_encrypt_key"]
}

rds_encrypt_key_err = "AWS RDS database not encrypted using Customer Managed Key" {
    aws_issue["rds_encrypt_key"]
}

rds_encrypt_key_metadata := {
    "Policy Code": "PR-AWS-0122-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS RDS database not encrypted using Customer Managed Key",
    "Policy Description": "This policy identifies RDS databases that are encrypted with default KMS keys and not with customer managed keys. As a best practice, use customer managed keys to encrypt the data on your RDS databases and maintain control of your keys and data on sensitive workloads.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html"
}

#
# PR-AWS-0123-TRF
#

default rds_instance_event = null

aws_issue["rds_instance_event"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_db_event_subscription"
    lower(resource.properties.enabled) == "false"
    resource.properties.source_type == "db-instance"
}

aws_bool_issue["rds_instance_event"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_db_event_subscription"
    resource.properties.enabled == false
    resource.properties.source_type == "db-instance"
}

rds_instance_event {
    lower(input.resources[i].type) == "aws_db_event_subscription"
    not aws_issue["rds_instance_event"]
    not aws_bool_issue["rds_instance_event"]
}

rds_instance_event = false {
    aws_issue["rds_instance_event"]
}

rds_instance_event = false {
    aws_bool_issue["rds_instance_event"]
}

rds_instance_event_err = "AWS RDS event subscription disabled for DB instance" {
    aws_issue["rds_instance_event"]
} else = "AWS RDS event subscription disabled for DB instance" {
    aws_bool_issue["rds_instance_event"]
}

rds_instance_event_metadata := {
    "Policy Code": "PR-AWS-0123-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS RDS event subscription disabled for DB instance",
    "Policy Description": "This policy identifies RDS event subscriptions for which DB instance event subscription is disabled. You can create an Amazon RDS event notification subscription so that you can be notified when an event occurs for a given DB instance.",
    "Resource Type": "aws_db_event_subscription",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html"
}

#
# PR-AWS-0124-TRF
#

default rds_secgroup_event = null

aws_issue["rds_secgroup_event"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_db_event_subscription"
    lower(resource.properties.enabled) == "false"
    resource.properties.source_type == "db-security-group"
}

aws_bool_issue["rds_secgroup_event"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_db_event_subscription"
    resource.properties.enabled == false
    resource.properties.source_type == "db-security-group"
}


rds_secgroup_event {
    lower(input.resources[i].type) == "aws_db_event_subscription"
    not aws_issue["rds_secgroup_event"]
    not aws_bool_issue["rds_secgroup_event"]
}

rds_secgroup_event = false {
    aws_issue["rds_secgroup_event"]
}

rds_secgroup_event = false {
    aws_bool_issue["rds_secgroup_event"]
}

rds_secgroup_event_err = "AWS RDS event subscription disabled for DB security groups" {
    aws_issue["rds_secgroup_event"]
} else = "AWS RDS event subscription disabled for DB security groups" {
    aws_bool_issue["rds_secgroup_event"]
}


rds_secgroup_event_metadata := {
    "Policy Code": "PR-AWS-0124-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS RDS event subscription disabled for DB security groups",
    "Policy Description": "This policy identifies RDS event subscriptions for which DB security groups event subscription is disabled. You can create an Amazon RDS event notification subscription so that you can be notified when an event occurs for given DB security groups.",
    "Resource Type": "aws_db_event_subscription",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html"
}


#
# PR-AWS-0125-TRF
#

default rds_encrypt = null

aws_issue["rds_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_db_instance"
    lower(resource.properties.storage_encrypted) == "false"
}

aws_bool_issue["rds_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_db_instance"
    not resource.properties.storage_encrypted
}

rds_encrypt {
    lower(input.resources[_].type) == "aws_db_instance"
    not aws_issue["rds_encrypt"]
    not aws_bool_issue["rds_encrypt"]
}

rds_encrypt = false {
    aws_issue["rds_encrypt"]
}

rds_encrypt = false {
    aws_bool_issue["rds_encrypt"]
}

rds_encrypt_err = "AWS RDS instance is not encrypted" {
    aws_issue["rds_encrypt"]
} else = "AWS RDS instance is not encrypted" {
    aws_bool_issue["rds_encrypt"]
}

rds_encrypt_metadata := {
    "Policy Code": "PR-AWS-0125-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS RDS instance is not encrypted",
    "Policy Description": "This policy identifies AWS RDS instances which are not encrypted. Amazon Relational Database Service (Amazon RDS) is a web service that makes it easier to set up and manage databases. Amazon allows customers to turn on encryption for RDS which is recommended for compliance and security reasons.",
    "Resource Type": "aws_db_instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html"
}

#
# PR-AWS-0127-TRF
#

default rds_multiaz = null

aws_attribute_absence["rds_multiaz"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_db_instance"
    not resource.properties.engine
}

aws_issue["rds_multiaz"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_db_instance"
    lower(resource.properties.engine) != "aurora"
    lower(resource.properties.engine) != "sqlserver"
    lower(resource.properties.multi_az) == "false"
}

aws_bool_issue["rds_multiaz"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_db_instance"
    lower(resource.properties.engine) != "aurora"
    lower(resource.properties.engine) != "sqlserver"
    not resource.properties.multi_az
}

rds_multiaz {
    lower(input.resources[_].type) == "aws_db_instance"
    not aws_issue["rds_multiaz"]
    not aws_bool_issue["rds_multiaz"]
    not aws_attribute_absence["rds_multiaz"]
}

rds_multiaz = false {
    aws_issue["rds_multiaz"]
}

rds_multiaz = false {
    aws_bool_issue["rds_multiaz"]
}

rds_multiaz = false {
    aws_attribute_absence["rds_multiaz"]
}

rds_multiaz_err = "AWS RDS instance with Multi-Availability Zone disabled" {
    aws_issue["rds_multiaz"]
} else = "AWS RDS instance with Multi-Availability Zone disabled" {
    aws_bool_issue["rds_multiaz"]
} else = "RDS dbcluster attribute engine missing in the resource" {
    aws_attribute_absence["rds_multiaz"]
}

rds_multiaz_metadata := {
    "Policy Code": "PR-AWS-0127-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS RDS instance with Multi-Availability Zone disabled",
    "Policy Description": "This policy identifies RDS instances which have Multi-Availability Zone(Multi-AZ) disabled. When RDS DB instance is enabled with Multi-AZ, RDS automatically creates a primary DB Instance and synchronously replicates the data to a standby instance in a different availability zone. These Multi-AZ deployments will improve primary node reachability by providing read replica in case of network connectivity loss or loss of availability in the primaryâ€™s availability zone for read/write operations, so by making them the best fit for production database workloads.",
    "Resource Type": "aws_db_instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html"
}

#
# PR-AWS-0128-TRF
#

default rds_snapshot = null

aws_issue["rds_snapshot"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_db_instance"
    lower(resource.properties.copy_tags_to_snapshot) == "false"
}

aws_bool_issue["rds_snapshot"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_db_instance"
    not resource.properties.copy_tags_to_snapshot
}

rds_snapshot {
    lower(input.resources[_].type) == "aws_db_instance"
    not aws_issue["rds_snapshot"]
    not aws_bool_issue["rds_snapshot"]
}

rds_snapshot = false {
    aws_issue["rds_snapshot"]
}

rds_snapshot = false {
    aws_bool_issue["rds_snapshot"]
}

rds_snapshot_err = "AWS RDS instance with copy tags to snapshots disabled" {
    aws_issue["rds_snapshot"]
} else = "AWS RDS instance with copy tags to snapshots disabled" {
    aws_bool_issue["rds_snapshot"]
}

rds_snapshot_metadata := {
    "Policy Code": "PR-AWS-0128-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS RDS instance with copy tags to snapshots disabled",
    "Policy Description": "This policy identifies RDS instances which have copy tags to snapshots disabled. Copy tags to snapshots copies all the user-defined tags from the DB instance to snapshots. Copying tags allow you to add metadata and apply access policies to your Amazon RDS resources.",
    "Resource Type": "aws_db_instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html"
}

#
# PR-AWS-0129-TRF
#

default rds_backup = null

aws_attribute_absence["rds_backup"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_db_instance"
    not resource.properties.backup_retention_period
}

aws_issue["rds_backup"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_db_instance"
    to_number(resource.properties.backup_retention_period) == 0
}

rds_backup {
    lower(input.resources[_].type) == "aws_db_instance"
    not aws_issue["rds_backup"]
    not aws_attribute_absence["rds_backup"]
}

rds_backup = false {
    aws_issue["rds_backup"]
}

rds_backup = false {
    aws_attribute_absence["rds_backup"]
}

rds_backup_err = "AWS RDS instance without Automatic Backup setting" {
    aws_issue["rds_backup"]
} else = "RDS attribute backup_retention_period missing in the resource" {
    aws_attribute_absence["rds_backup"]
}

rds_backup_metadata := {
    "Policy Code": "PR-AWS-0129-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS RDS instance without Automatic Backup setting",
    "Policy Description": "This policy identifies RDS instances which are not set with the Automatic Backup setting. If Automatic Backup is set, RDS creates a storage volume snapshot of your DB instance, backing up the entire DB instance and not just individual databases which provide for point-in-time recovery. The automatic backup will happen during the specified backup window time and keeps the backups for a limited period of time as defined in the retention period. It is recommended to set Automatic backups for your critical RDS servers that will help in the data restoration process.",
    "Resource Type": "aws_db_instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html"
}

#
# PR-AWS-0130-TRF
#

default rds_upgrade = null

aws_issue["rds_upgrade"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_db_instance"
    lower(resource.properties.auto_minor_version_upgrade) == "false"
}

aws_bool_issue["rds_upgrade"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_db_instance"
    not resource.properties.auto_minor_version_upgrade
}

rds_upgrade {
    lower(input.resources[_].type) == "aws_db_instance"
    not aws_issue["rds_upgrade"]
    not aws_bool_issue["rds_upgrade"]
}

rds_upgrade = false {
    aws_issue["rds_upgrade"]
}

rds_upgrade = false {
    aws_bool_issue["rds_upgrade"]
}

rds_upgrade_err = "AWS RDS minor upgrades not enabled" {
    aws_issue["rds_upgrade"]
} else = "AWS RDS minor upgrades not enabled" {
    aws_bool_issue["rds_upgrade"]
}

rds_upgrade_metadata := {
    "Policy Code": "PR-AWS-0130-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS RDS minor upgrades not enabled",
    "Policy Description": "When Amazon Relational Database Service (Amazon RDS) supports a new version of a database engine, you can upgrade your DB instances to the new version. There are two kinds of upgrades: major version upgrades and minor version upgrades. Minor upgrades helps maintain a secure and stable RDS with minimal impact on the application. For this reason, we recommend that your automatic minor upgrade is enabled. Minor version upgrades only occur automatically if a minor upgrade replaces an unsafe version, such as a minor upgrade that contains bug fixes for a previous version.",
    "Resource Type": "aws_db_instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html"
}

#
# PR-AWS-0131-TRF
#

default rds_retention = null

aws_attribute_absence["rds_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_db_instance"
    not resource.properties.backup_retention_period
}

aws_issue["rds_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_db_instance"
    to_number(resource.properties.backup_retention_period) < 7
}

rds_retention {
    lower(input.resources[_].type) == "aws_db_instance"
    not aws_issue["rds_retention"]
    not aws_attribute_absence["rds_retention"]
}

rds_retention = false {
    aws_issue["rds_retention"]
}

rds_retention = false {
    aws_attribute_absence["rds_retention"]
}

rds_retention_err = "AWS RDS retention policy less than 7 days" {
    aws_issue["rds_retention"]
} else = "RDS attribute backup_retention_period missing in the resource" {
    aws_attribute_absence["rds_retention"]
}

rds_retention_metadata := {
    "Policy Code": "PR-AWS-0131-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS RDS retention policy less than 7 days",
    "Policy Description": "RDS Retention Policies for Backups are an important part of your DR/BCP strategy. Recovering data from catastrophic failures, malicious attacks, or corruption often requires a several day window of potentially good backup material to leverage. As such, the best practice is to ensure your RDS clusters are retaining at least 7 days of backups, if not more (up to a maximum of 35).",
    "Resource Type": "aws_db_instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html"
}

#
# PR-AWS-0244-TRF
#

default rds_cluster_retention = null

aws_attribute_absence["rds_cluster_retention"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_rds_cluster"
    not resource.properties.backup_retention_period
}

aws_issue["rds_cluster_retention"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_rds_cluster"
    to_number(resource.properties.backup_retention_period) < 7
}

rds_cluster_retention {
    lower(input.resources[i].type) == "aws_rds_cluster"
    not aws_issue["rds_cluster_retention"]
    not aws_attribute_absence["rds_cluster_retention"]
}

rds_cluster_retention = false {
    aws_issue["rds_cluster_retention"]
}

rds_cluster_retention = false {
    aws_attribute_absence["rds_cluster_retention"]
}

rds_cluster_retention_err = "AWS RDS retention policy less than 7 days" {
    aws_issue["rds_cluster_retention"]
}

rds_cluster_retention_miss_err = "RDS attribute BackupRetentionPeriod missing in the resource" {
    aws_attribute_absence["rds_cluster_retention"]
}

rds_cluster_retention_metadata := {
    "Policy Code": "PR-AWS-0244-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS RDS cluster retention policy less than 7 days",
    "Policy Description": "RDS cluster Retention Policies for Backups are an important part of your DR/BCP strategy. Recovering data from catastrophic failures, malicious attacks, or corruption often requires a several day window of potentially good backup material to leverage. As such, the best practice is to ensure your RDS clusters are retaining at least 7 days of backups, if not more (up to a maximum of 35).",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html"
}

#
# PR-AWS-0262-TRF
#

default rds_cluster_deletion_protection = null

aws_issue["rds_cluster_deletion_protection"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_rds_cluster"
    lower(resource.properties.deletion_protection) != "true"
}

aws_bool_issue["rds_cluster_deletion_protection"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_rds_cluster"
    not resource.properties.deletion_protection
}

rds_cluster_deletion_protection {
    lower(input.resources[i].type) == "aws_rds_cluster"
    not aws_issue["rds_cluster_deletion_protection"]
    not aws_bool_issue["rds_cluster_deletion_protection"]
}

rds_cluster_deletion_protection = false {
    aws_issue["rds_cluster_deletion_protection"]
}

rds_cluster_deletion_protection = false {
    aws_bool_issue["rds_cluster_deletion_protection"]
}

rds_cluster_deletion_protection_err = "Ensure RDS clusters and instances have deletion protection enabled" {
    aws_issue["rds_cluster_deletion_protection"]
} else = "Ensure RDS clusters and instances have deletion protection enabled" {
    aws_bool_issue["rds_cluster_deletion_protection"]
}

rds_cluster_deletion_protection_metadata := {
    "Policy Code": "PR-AWS-0262-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure RDS clusters and instances have deletion protection enabled",
    "Policy Description": "This rule Checks if an Amazon Relational Database Service (Amazon RDS) cluster has deletion protection enabled",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html"
}
