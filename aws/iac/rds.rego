package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html
# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-rds-database-instance.html

#
# PR-AWS-0119-CFR
#

default rds_cluster_encrypt = null

aws_issue["rds_cluster_encrypt"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::rds::dbcluster"
    lower(resource.Properties.StorageEncrypted) == "false"
}

aws_bool_issue["rds_cluster_encrypt"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::rds::dbcluster"
    not resource.Properties.StorageEncrypted
}

rds_cluster_encrypt {
    lower(input.Resources[i].Type) == "aws::rds::dbcluster"
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
    "Policy Code": "PR-AWS-0119-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS RDS DB cluster encryption is disabled",
    "Policy Description": "This policy identifies RDS DB clusters for which encryption is disabled. Amazon Aurora encrypted DB clusters provide an additional layer of data protection by securing your data from unauthorized access to the underlying storage. You can use Amazon Aurora encryption to increase data protection of your applications deployed in the cloud, and to fulfill compliance requirements for data-at-rest encryption.</br> NOTE: This policy is applicable only for Aurora DB clusters.</br> https://docs.aws.amazon.com/cli/latest/reference/rds/describe-db-clusters.html",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html"
}

#
# PR-AWS-0121-CFR
#

default rds_public = null

aws_issue["rds_public"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::rds::dbinstance"
    lower(resource.Properties.PubliclyAccessible) == "true"
}

aws_bool_issue["rds_public"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::rds::dbinstance"
    resource.Properties.PubliclyAccessible == true
}

rds_public {
    lower(input.Resources[i].Type) == "aws::rds::dbinstance"
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
    "Policy Code": "PR-AWS-0121-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS RDS database instance is publicly accessible",
    "Policy Description": "This policy identifies RDS database instances which are publicly accessible.DB instances should not be publicly accessible to protect the integrety of data.Public accessibility of DB instances can be modified by turning on or off the Public accessibility parameter.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html"
}

#
# PR-AWS-0122-CFR
#

default rds_encrypt_key = null

aws_issue["rds_encrypt_key"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::rds::dbinstance"
    not resource.Properties.KmsKeyId
}

aws_issue["rds_encrypt_key"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::rds::dbinstance"
    count(resource.Properties.KmsKeyId) == 0
}

rds_encrypt_key {
    lower(input.Resources[i].Type) == "aws::rds::dbinstance"
    not aws_issue["rds_encrypt_key"]
}

rds_encrypt_key = false {
    aws_issue["rds_encrypt_key"]
}

rds_encrypt_key_err = "AWS RDS database not encrypted using Customer Managed Key" {
    aws_issue["rds_encrypt_key"]
}

rds_encrypt_key_metadata := {
    "Policy Code": "PR-AWS-0122-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS RDS database not encrypted using Customer Managed Key",
    "Policy Description": "This policy identifies RDS databases that are encrypted with default KMS keys and not with customer managed keys. As a best practice, use customer managed keys to encrypt the data on your RDS databases and maintain control of your keys and data on sensitive workloads.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html"
}

#
# PR-AWS-0123-CFR
#

default rds_instance_event = null

aws_issue["rds_instance_event"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::rds::eventsubscription"
    lower(resource.Properties.Enabled) == "false"
    resource.Properties.SourceType == "db-instance"
}

aws_bool_issue["rds_instance_event"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::rds::eventsubscription"
    resource.Properties.Enabled == false
    resource.Properties.SourceType == "db-instance"
}

rds_instance_event {
    lower(input.Resources[i].Type) == "aws::rds::eventsubscription"
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
    "Policy Code": "PR-AWS-0123-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS RDS event subscription disabled for DB instance",
    "Policy Description": "This policy identifies RDS event subscriptions for which DB instance event subscription is disabled. You can create an Amazon RDS event notification subscription so that you can be notified when an event occurs for a given DB instance.",
    "Resource Type": "aws::rds::eventsubscription",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html"
}

#
# PR-AWS-0124-CFR
#

default rds_secgroup_event = null

aws_issue["rds_secgroup_event"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::rds::eventsubscription"
    lower(resource.Properties.Enabled) == "false"
    resource.Properties.SourceType == "db-security-group"
}

aws_bool_issue["rds_secgroup_event"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::rds::eventsubscription"
    resource.Properties.Enabled == false
    resource.Properties.SourceType == "db-security-group"
}


rds_secgroup_event {
    lower(input.Resources[i].Type) == "aws::rds::eventsubscription"
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
    "Policy Code": "PR-AWS-0124-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS RDS event subscription disabled for DB security groups",
    "Policy Description": "This policy identifies RDS event subscriptions for which DB security groups event subscription is disabled. You can create an Amazon RDS event notification subscription so that you can be notified when an event occurs for given DB security groups.",
    "Resource Type": "aws::rds::eventsubscription",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html"
}

#
# PR-AWS-0125-CFR
#

default rds_encrypt = null

aws_issue["rds_encrypt"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::rds::dbinstance"
    lower(resource.Properties.StorageEncrypted) == "false"
}

aws_bool_issue["rds_encrypt"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::rds::dbinstance"
    not resource.Properties.StorageEncrypted
}

rds_encrypt {
    lower(input.Resources[i].Type) == "aws::rds::dbinstance"
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
    "Policy Code": "PR-AWS-0125-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS RDS instance is not encrypted",
    "Policy Description": "This policy identifies AWS RDS instances which are not encrypted. Amazon Relational Database Service (Amazon RDS) is a web service that makes it easier to set up and manage databases. Amazon allows customers to turn on encryption for RDS which is recommended for compliance and security reasons.",
    "Resource Type": "aws::rds::dbinstance",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html"
}

#
# PR-AWS-0127-CFR
#

default rds_multiaz = null


aws_issue["rds_multiaz"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::rds::dbinstance"
    lower(resource.Properties.Engine) != "aurora"
    lower(resource.Properties.Engine) != "sqlserver"
    lower(resource.Properties.MultiAZ) == "false"
}

aws_bool_issue["rds_multiaz"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::rds::dbinstance"
    lower(resource.Properties.Engine) != "aurora"
    lower(resource.Properties.Engine) != "sqlserver"
    not resource.Properties.MultiAZ
}

rds_multiaz {
    lower(input.Resources[i].Type) == "aws::rds::dbinstance"
    not aws_issue["rds_multiaz"]
    not aws_bool_issue["rds_multiaz"]
}

rds_multiaz = false {
    aws_issue["rds_multiaz"]
}

rds_multiaz = false {
    aws_bool_issue["rds_multiaz"]
}

rds_multiaz_err = "AWS RDS instance with Multi-Availability Zone disabled" {
    aws_issue["rds_multiaz"]
} else = "AWS RDS instance with Multi-Availability Zone disabled" {
    aws_bool_issue["rds_multiaz"]
}

rds_multiaz_metadata := {
    "Policy Code": "PR-AWS-0127-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS RDS instance with Multi-Availability Zone disabled",
    "Policy Description": "This policy identifies RDS instances which have Multi-Availability Zone(Multi-AZ) disabled. When RDS DB instance is enabled with Multi-AZ, RDS automatically creates a primary DB Instance and synchronously replicates the data to a standby instance in a different availability zone. These Multi-AZ deployments will improve primary node reachability by providing read replica in case of network connectivity loss or loss of availability in the primaryâ€™s availability zone for read/write operations, so by making them the best fit for production database workloads.",
    "Resource Type": "aws::rds::dbinstance",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html"
}

#
# PR-AWS-0128-CFR
#

default rds_snapshot = null

aws_issue["rds_snapshot"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::rds::dbinstance"
    lower(resource.Properties.CopyTagsToSnapshot) == "false"
}

aws_bool_issue["rds_snapshot"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::rds::dbinstance"
    not resource.Properties.CopyTagsToSnapshot
}

rds_snapshot {
    lower(input.Resources[i].Type) == "aws::rds::dbinstance"
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
    "Policy Code": "PR-AWS-0128-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS RDS instance with copy tags to snapshots disabled",
    "Policy Description": "This policy identifies RDS instances which have copy tags to snapshots disabled. Copy tags to snapshots copies all the user-defined tags from the DB instance to snapshots. Copying tags allow you to add metadata and apply access policies to your Amazon RDS resources.",
    "Resource Type": "aws::rds::dbinstance",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html"
}

#
# PR-AWS-0129-CFR
#

default rds_backup = null

aws_attribute_absence["rds_backup"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::rds::dbinstance"
    not resource.Properties.BackupRetentionPeriod
}

aws_issue["rds_backup"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::rds::dbinstance"
    to_number(resource.Properties.BackupRetentionPeriod) == 0
}

rds_backup {
    lower(input.Resources[i].Type) == "aws::rds::dbinstance"
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
}

rds_backup_miss_err = "RDS attribute BackupRetentionPeriod missing in the resource" {
    aws_attribute_absence["rds_backup"]
}

rds_backup_metadata := {
    "Policy Code": "PR-AWS-0129-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS RDS instance without Automatic Backup setting",
    "Policy Description": "This policy identifies RDS instances which are not set with the Automatic Backup setting. If Automatic Backup is set, RDS creates a storage volume snapshot of your DB instance, backing up the entire DB instance and not just individual databases which provide for point-in-time recovery. The automatic backup will happen during the specified backup window time and keeps the backups for a limited period of time as defined in the retention period. It is recommended to set Automatic backups for your critical RDS servers that will help in the data restoration process.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html"
}

#
# PR-AWS-0130-CFR
#

default rds_upgrade = null

aws_issue["rds_upgrade"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::rds::dbinstance"
    lower(resource.Properties.AutoMinorVersionUpgrade) == "false"
}

aws_bool_issue["rds_upgrade"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::rds::dbinstance"
    not resource.Properties.AutoMinorVersionUpgrade
}

rds_upgrade {
    lower(input.Resources[i].Type) == "aws::rds::dbinstance"
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
    "Policy Code": "PR-AWS-0130-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS RDS minor upgrades not enabled",
    "Policy Description": "When Amazon Relational Database Service (Amazon RDS) supports a new version of a database engine, you can upgrade your DB instances to the new version. There are two kinds of upgrades: major version upgrades and minor version upgrades. Minor upgrades helps maintain a secure and stable RDS with minimal impact on the application. For this reason, we recommend that your automatic minor upgrade is enabled. Minor version upgrades only occur automatically if a minor upgrade replaces an unsafe version, such as a minor upgrade that contains bug fixes for a previous version.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html"
}

#
# PR-AWS-0131-CFR
#

default rds_retention = null

aws_attribute_absence["rds_retention"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::rds::dbinstance"
    not resource.Properties.BackupRetentionPeriod
}

aws_issue["rds_retention"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::rds::dbinstance"
    to_number(resource.Properties.BackupRetentionPeriod) < 7
}

rds_retention {
    lower(input.Resources[i].Type) == "aws::rds::dbinstance"
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
}

rds_retention_miss_err = "RDS attribute BackupRetentionPeriod missing in the resource" {
    aws_attribute_absence["rds_retention"]
}

rds_retention_metadata := {
    "Policy Code": "PR-AWS-0131-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS RDS retention policy less than 7 days",
    "Policy Description": "RDS Retention Policies for Backups are an important part of your DR/BCP strategy. Recovering data from catastrophic failures, malicious attacks, or corruption often requires a several day window of potentially good backup material to leverage. As such, the best practice is to ensure your RDS clusters are retaining at least 7 days of backups, if not more (up to a maximum of 35).",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html"
}


#
# PR-AWS-0244-CFR
#

default rds_cluster_retention = null

aws_attribute_absence["rds_cluster_retention"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::rds::dbcluster"
    not resource.Properties.BackupRetentionPeriod
}

aws_issue["rds_cluster_retention"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::rds::dbcluster"
    to_number(resource.Properties.BackupRetentionPeriod) < 7
}

rds_cluster_retention {
    lower(input.Resources[i].Type) == "aws::rds::dbcluster"
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
    "Policy Code": "PR-AWS-0244-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS RDS cluster retention policy less than 7 days",
    "Policy Description": "RDS cluster Retention Policies for Backups are an important part of your DR/BCP strategy. Recovering data from catastrophic failures, malicious attacks, or corruption often requires a several day window of potentially good backup material to leverage. As such, the best practice is to ensure your RDS clusters are retaining at least 7 days of backups, if not more (up to a maximum of 35).",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html"
}


#
# PR-AWS-0262-CFR
#

default rds_cluster_deletion_protection = null

aws_issue["rds_cluster_deletion_protection"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::rds::dbcluster"
    lower(resource.Properties.DeletionProtection) != "true"
}

aws_bool_issue["rds_cluster_deletion_protection"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::rds::dbcluster"
    not resource.Properties.DeletionProtection
}

rds_cluster_deletion_protection {
    lower(input.Resources[i].Type) == "aws::rds::dbcluster"
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
    "Policy Code": "PR-AWS-0262-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure RDS clusters and instances have deletion protection enabled",
    "Policy Description": "This rule Checks if an Amazon Relational Database Service (Amazon RDS) cluster has deletion protection enabled",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html"
}


#
# PR-AWS-0299-CFR
#

default rds_pgaudit_enable = null

aws_issue["rds_pgaudit_enable"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::rds::dbparametergroup"
    count([c | resource.Properties.Parameters["pgaudit.role"] == "rds_pgaudit" ; c := 1]) == 0
}

aws_issue["rds_pgaudit_enable"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::rds::dbparametergroup"
    not resource.Properties.Parameters
}

rds_pgaudit_enable {
    lower(input.Resources[i].Type) == "aws::rds::dbparametergroup"
    not aws_issue["rds_pgaudit_enable"]
}

rds_pgaudit_enable = false {
    aws_issue["rds_pgaudit_enable"]
}

rds_pgaudit_enable_err = "AWS RDS retention policy less than 7 days" {
    aws_issue["rds_pgaudit_enable"]
}

rds_pgaudit_enable_metadata := {
    "Policy Code": "PR-AWS-0299-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure PGAudit is enabled on RDS Postgres instances",
    "Policy Description": "Postgres database instances can be enabled for auditing with PGAudit, the PostgresSQL Audit Extension. With PGAudit enabled you will be able to audit any database, its roles, relations, or columns.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-rds-dbparametergroup.html#cfn-rds-dbparametergroup-parameters"
}

#
# PR-AWS-0300-CFR
#

default rds_global_cluster_encrypt = null

aws_issue["rds_global_cluster_encrypt"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::rds::globalcluster"
    lower(resource.Properties.StorageEncrypted) == "false"
}

aws_bool_issue["rds_global_cluster_encrypt"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::rds::globalcluster"
    not resource.Properties.StorageEncrypted
}

rds_global_cluster_encrypt {
    lower(input.Resources[i].Type) == "aws::rds::globalcluster"
    not aws_issue["rds_global_cluster_encrypt"]
    not aws_bool_issue["rds_global_cluster_encrypt"]
}

rds_global_cluster_encrypt = false {
    aws_issue["rds_global_cluster_encrypt"]
}

rds_global_cluster_encrypt = false {
    aws_bool_issue["rds_global_cluster_encrypt"]
}

rds_global_cluster_encrypt_err = "AWS RDS Global DB cluster encryption is disabled" {
    aws_issue["rds_global_cluster_encrypt"]
} else = "AWS RDS Global DB cluster encryption is disabled" {
    aws_bool_issue["rds_global_cluster_encrypt"]
}

rds_global_cluster_encrypt_metadata := {
    "Policy Code": "PR-AWS-0300-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS RDS Global DB cluster encryption is disabled",
    "Policy Description": "This policy identifies RDS Global DB clusters for which encryption is disabled. Amazon Aurora encrypted Global DB clusters provide an additional layer of data protection by securing your data from unauthorized access to the underlying storage. You can use Amazon Aurora encryption to increase data protection of your applications deployed in the cloud, and to fulfill compliance requirements",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-globalcluster.html"
}

#
# PR-AWS-0312-CFR
#

default cluster_iam_authenticate = null

aws_issue["cluster_iam_authenticate"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::rds::dbcluster"
    lower(resource.Properties.EnableIAMDatabaseAuthentication) == "false"
}

aws_bool_issue["cluster_iam_authenticate"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::rds::dbcluster"
    not resource.Properties.EnableIAMDatabaseAuthentication
}

cluster_iam_authenticate {
    lower(input.Resources[i].Type) == "aws::rds::dbcluster"
    not aws_issue["cluster_iam_authenticate"]
    not aws_bool_issue["cluster_iam_authenticate"]
}

cluster_iam_authenticate = false {
    aws_issue["cluster_iam_authenticate"]
}

cluster_iam_authenticate = false {
    aws_bool_issue["cluster_iam_authenticate"]
}

cluster_iam_authenticate_err = "Ensure RDS cluster has IAM authentication enabled" {
    aws_issue["cluster_iam_authenticate"]
} else = "Ensure RDS cluster has IAM authentication enabled" {
    aws_bool_issue["cluster_iam_authenticate"]
}

cluster_iam_authenticate_metadata := {
    "Policy Code": "PR-AWS-0312-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure RDS cluster has IAM authentication enabled",
    "Policy Description": "Ensure IAM Database Authentication feature is enabled in order to use AWS Identity and Access Management (IAM) service to manage database access to your Amazon RDS MySQL and PostgreSQL instances. With this feature enabled, you don't have to use a password when you connect to your MySQL/PostgreSQL database instances, instead you use an authentication token",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html#cfn-rds-dbcluster-enableiamdatabaseauthentication"
}

#
# PR-AWS-0314-CFR
#

default db_instance_iam_authenticate = null

aws_issue["db_instance_iam_authenticate"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::rds::dbinstance"
    lower(resource.Properties.EnableIAMDatabaseAuthentication) == "false"
}

aws_bool_issue["db_instance_iam_authenticate"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::rds::dbinstance"
    not resource.Properties.EnableIAMDatabaseAuthentication
}

db_instance_iam_authenticate {
    lower(input.Resources[i].Type) == "aws::rds::dbinstance"
    not aws_issue["db_instance_iam_authenticate"]
    not aws_bool_issue["db_instance_iam_authenticate"]
}

db_instance_iam_authenticate = false {
    aws_issue["db_instance_iam_authenticate"]
}

db_instance_iam_authenticate = false {
    aws_bool_issue["db_instance_iam_authenticate"]
}

db_instance_iam_authenticate_err = "Ensure RDS instance has IAM authentication enabled" {
    aws_issue["db_instance_iam_authenticate"]
} else = "Ensure RDS instace has IAM authentication enabled" {
    aws_bool_issue["db_instance_iam_authenticate"]
}

db_instance_iam_authenticate_metadata := {
    "Policy Code": "PR-AWS-0314-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure RDS instace has IAM authentication enabled",
    "Policy Description": "Ensure IAM Database Authentication feature is enabled in order to use AWS Identity and Access Management (IAM) service to manage database access to your Amazon RDS MySQL and PostgreSQL instances. With this feature enabled, you don't have to use a password when you connect to your MySQL/PostgreSQL database instances, instead you use an authentication token",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-rds-database-instance.html#cfn-rds-dbinstance-enableiamdatabaseauthentication"
}


#
# PR-AWS-0320-CFR
#

default db_instance_cloudwatch_logs = null

aws_issue["db_instance_cloudwatch_logs"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::rds::dbinstance"
    count(resource.Properties.EnableCloudwatchLogsExports) == 0
}

aws_issue["db_instance_cloudwatch_logs"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::rds::dbinstance"
    not resource.Properties.EnableCloudwatchLogsExports
}

db_instance_cloudwatch_logs {
    lower(input.Resources[i].Type) == "aws::rds::dbinstance"
    not aws_issue["db_instance_cloudwatch_logs"]
}

db_instance_cloudwatch_logs = false {
    aws_issue["db_instance_cloudwatch_logs"]
}

db_instance_cloudwatch_logs_err = "Ensure respective logs of Amazon RDS instance are enabled" {
    aws_issue["db_instance_cloudwatch_logs"]
}

db_instance_cloudwatch_logs_metadata := {
    "Policy Code": "PR-AWS-0320-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure respective logs of Amazon RDS instance are enabled",
    "Policy Description": "Use CloudWatch logging types for Amazon Relational Database Service (Amazon RDS) instances",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-rds-database-instance.html#cfn-rds-dbinstance-enablecloudwatchlogsexports"
}



#
# PR-AWS-0321-CFR
#

default db_instance_monitor = null

aws_issue["db_instance_monitor"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::rds::dbinstance"
    not resource.Properties.MonitoringInterval
}

db_instance_monitor {
    lower(input.Resources[i].Type) == "aws::rds::dbinstance"
    not aws_issue["db_instance_monitor"]
}

db_instance_monitor = false {
    aws_issue["db_instance_monitor"]
}

db_instance_monitor_err = "Enhanced monitoring for Amazon RDS instances is enabled" {
    aws_issue["db_instance_monitor"]
}

db_instance_monitor_metadata := {
    "Policy Code": "PR-AWS-0321-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Enhanced monitoring for Amazon RDS instances is enabled",
    "Policy Description": "This New Relic integration allows you to monitor and alert on RDS Enhanced Monitoring. You can use integration data and alerts to monitor the DB processes and identify potential trouble spots as well as to profile the DB allowing you to improve and optimize their response and cost",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-rds-database-instance.html#cfn-rds-dbinstance-monitoringinterval"
}
