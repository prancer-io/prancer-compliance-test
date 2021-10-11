package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html
# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-rds-database-instance.html

#
# PR-AWS-CFR-RDS-001
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
    "Policy Code": "PR-AWS-CFR-RDS-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS RDS DB cluster encryption is disabled",
    "Policy Description": "This policy identifies RDS DB clusters for which encryption is disabled. Amazon Aurora encrypted DB clusters provide an additional layer of data protection by securing your data from unauthorized access to the underlying storage. You can use Amazon Aurora encryption to increase data protection of your applications deployed in the cloud, and to fulfill compliance requirements for data-at-rest encryption._x005F_x000D_ NOTE: This policy is applicable only for Aurora DB clusters._x005F_x000D_ https://docs.aws.amazon.com/cli/latest/reference/rds/describe-db-clusters.html",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html"
}

#
# PR-AWS-CFR-RDS-002
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
    "Policy Code": "PR-AWS-CFR-RDS-002",
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
# PR-AWS-CFR-RDS-003
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
    "Policy Code": "PR-AWS-CFR-RDS-003",
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
# PR-AWS-CFR-RDS-004
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
    "Policy Code": "PR-AWS-CFR-RDS-004",
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
# PR-AWS-CFR-RDS-005
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
    "Policy Code": "PR-AWS-CFR-RDS-005",
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
# PR-AWS-CFR-RDS-006
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
    "Policy Code": "PR-AWS-CFR-RDS-006",
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
# PR-AWS-CFR-RDS-007
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
    "Policy Code": "PR-AWS-CFR-RDS-007",
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
# PR-AWS-CFR-RDS-008
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
    "Policy Code": "PR-AWS-CFR-RDS-008",
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
# PR-AWS-CFR-RDS-009
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
    "Policy Code": "PR-AWS-CFR-RDS-009",
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
# PR-AWS-CFR-RDS-010
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
    "Policy Code": "PR-AWS-CFR-RDS-010",
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
# PR-AWS-CFR-RDS-011
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
    "Policy Code": "PR-AWS-CFR-RDS-011",
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
# PR-AWS-CFR-RDS-012
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
    "Policy Code": "PR-AWS-CFR-RDS-012",
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
# PR-AWS-CFR-RDS-013
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
    "Policy Code": "PR-AWS-CFR-RDS-013",
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
# PR-AWS-CFR-RDS-014
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
    "Policy Code": "PR-AWS-CFR-RDS-014",
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
# PR-AWS-CFR-RDS-015
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
    "Policy Code": "PR-AWS-CFR-RDS-015",
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
# PR-AWS-CFR-RDS-016
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
    "Policy Code": "PR-AWS-CFR-RDS-016",
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
# PR-AWS-CFR-RDS-017
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
    "Policy Code": "PR-AWS-CFR-RDS-017",
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
# PR-AWS-CFR-RDS-018
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
    "Policy Code": "PR-AWS-CFR-RDS-018",
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
# PR-AWS-CFR-RDS-019
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
    "Policy Code": "PR-AWS-CFR-RDS-019",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Enhanced monitoring for Amazon RDS instances is enabled",
    "Policy Description": "This New Relic integration allows you to monitor and alert on RDS Enhanced Monitoring. You can use integration data and alerts to monitor the DB processes and identify potential trouble spots as well as to profile the DB allowing you to improve and optimize their response and cost",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-rds-database-instance.html#cfn-rds-dbinstance-monitoringinterval"
}


#
# PR-AWS-CFR-DAX-001
#

default dax_encrypt = null

aws_issue["dax_encrypt"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::dax::cluster"
    lower(resource.Properties.SSESpecification.SSEEnabled) != "true"
}

aws_bool_issue["dax_encrypt"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::dax::cluster"
    not resource.Properties.SSESpecification.SSEEnabled
}

dax_encrypt {
    lower(input.Resources[i].Type) == "aws::dax::cluster"
    not aws_issue["dax_encrypt"]
    not aws_bool_issue["dax_encrypt"]
}

dax_encrypt = false {
    aws_issue["dax_encrypt"]
}

dax_encrypt = false {
    aws_bool_issue["dax_encrypt"]
}

dax_encrypt_err = "Ensure DAX is securely encrypted at rest" {
    aws_issue["dax_encrypt"]
} else = "Ensure DAX is securely encrypted at rest" {
    aws_bool_issue["dax_encrypt"]
}

dax_encrypt_metadata := {
    "Policy Code": "PR-AWS-CFR-DAX-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure DAX is securely encrypted at rest",
    "Policy Description": "Amazon DynamoDB Accelerator (DAX) encryption at rest provides an additional layer of data protection, helping secure your data from unauthorized access to underlying storage. With encryption at rest the data persisted by DAX on disk is encrypted using 256-bit Advanced Encryption Standard (AES-256). DAX writes data to disk as part of propagating changes from the primary node to read replicas. DAX encryption at rest automatically integrates with AWS KMS for managing the single service default key used to encrypt clusters.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dax-cluster-ssespecification.html"
}


#
# PR-AWS-CFR-QLDB-001
#

default qldb_permission_mode = null

aws_issue["qldb_permission_mode"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::qldb::ledger"
    lower(resource.Properties.PermissionsMode) != "standard"
}

aws_issue["qldb_permission_mode"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::qldb::ledger"
    not resource.Properties.PermissionsMode
}

qldb_permission_mode {
    lower(input.Resources[i].Type) == "aws::qldb::ledger"
    not aws_issue["qldb_permission_mode"]
}

qldb_permission_mode = false {
    aws_issue["qldb_permission_mode"]
}

qldb_permission_mode_err = "Ensure QLDB ledger permissions mode is set to STANDARD" {
    aws_issue["qldb_permission_mode"]
}

qldb_permission_mode_metadata := {
    "Policy Code": "PR-AWS-CFR-QLDB-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure QLDB ledger permissions mode is set to STANDARD",
    "Policy Description": "In Amazon Quantum Ledger Database define PermissionsMode value to STANDARD permissions mode that enables access control with finer granularity for ledgers, tables, and PartiQL commands",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-qldb-ledger.html#cfn-qldb-ledger-permissionsmode"
}



#
# PR-AWS-CFR-DDB-001
#

default docdb_cluster_encrypt = null

aws_issue["docdb_cluster_encrypt"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::docdb::dbcluster"
    not resource.Properties.StorageEncrypted
}

aws_issue["docdb_cluster_encrypt"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::docdb::dbcluster"
    lower(resource.Properties.StorageEncrypted) == "false"
}

docdb_cluster_encrypt {
    lower(input.Resources[i].Type) == "aws::docdb::dbcluster"
    not aws_issue["docdb_cluster_encrypt"]
}

docdb_cluster_encrypt = false {
    aws_issue["docdb_cluster_encrypt"]
}

docdb_cluster_encrypt_err = "Ensure DocumentDB cluster is encrypted at rest" {
    aws_issue["docdb_cluster_encrypt"]
}

docdb_cluster_encrypt_metadata := {
    "Policy Code": "PR-AWS-CFR-DDB-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure DocumentDB cluster is encrypted at rest",
    "Policy Description": "Ensure that encryption is enabled for your AWS DocumentDB (with MongoDB compatibility) clusters for additional data security and in order to meet compliance requirements for data-at-rest encryption",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html#cfn-docdb-dbcluster-storageencrypted"
}


#
# PR-AWS-CFR-DDB-002
#

default docdb_cluster_logs = null

aws_issue["docdb_cluster_logs"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::docdb::dbcluster"
    not resource.Properties.EnableCloudwatchLogsExports
}

aws_issue["docdb_cluster_logs"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::docdb::dbcluster"
    count(resource.Properties.EnableCloudwatchLogsExports) == 0
}

docdb_cluster_logs {
    lower(input.Resources[i].Type) == "aws::docdb::dbcluster"
    not aws_issue["docdb_cluster_logs"]
}

docdb_cluster_logs = false {
    aws_issue["docdb_cluster_logs"]
}

docdb_cluster_logs_err = "Ensure AWS DocumentDB logging is enabled" {
    aws_issue["docdb_cluster_logs"]
}

docdb_cluster_logs_metadata := {
    "Policy Code": "PR-AWS-CFR-DDB-002",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure AWS DocumentDB logging is enabled",
    "Policy Description": "The events recorded by the AWS DocumentDB audit logs include: successful and failed authentication attempts, creating indexes or dropping a collection in a database within the DocumentDB cluster.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html#cfn-docdb-dbcluster-enablecloudwatchlogsexports"
}

#
# PR-AWS-CFR-DDB-003
#

default docdb_parameter_group_tls_enable = null

aws_issue["docdb_parameter_group_tls_enable"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::docdb::dbclusterparametergroup"
    not resource.Properties.Parameters.tls
}

aws_issue["docdb_parameter_group_tls_enable"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::docdb::dbclusterparametergroup"
    lower(resource.Properties.Parameters.tls) != "enabled"
    not resource.Properties.Parameters.Value
}

docdb_parameter_group_tls_enable {
    lower(input.Resources[i].Type) == "aws::docdb::dbclusterparametergroup"
    not aws_issue["docdb_parameter_group_tls_enable"]
}

docdb_parameter_group_tls_enable = false {
    aws_issue["docdb_parameter_group_tls_enable"]
}

docdb_parameter_group_tls_enable_err = "Ensure DocDB ParameterGroup has TLS enable" {
    aws_issue["docdb_parameter_group_tls_enable"]
}

docdb_parameter_group_tls_enable_metadata := {
    "Policy Code": "PR-AWS-CFR-DDB-003",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure DocDB ParameterGroup has TLS enable",
    "Policy Description": "TLS can be used to encrypt the connection between an application and a DocDB cluster. By default, encryption in transit is enabled for newly created clusters. It can optionally be disabled when the cluster is created, or at a later time. When enabled, secure connections using TLS are required to connect to the cluster.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbclusterparametergroup.html#cfn-docdb-dbclusterparametergroup-parameters"
}


#
# PR-AWS-CFR-DDB-004
#

default docdb_parameter_group_audit_logs = null

aws_issue["docdb_parameter_group_audit_logs"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::docdb::dbclusterparametergroup"
    not resource.Properties.Parameters.audit_logs
}

aws_issue["docdb_parameter_group_audit_logs"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::docdb::dbclusterparametergroup"
    lower(resource.Properties.Parameters.audit_logs) != "enabled"
}

docdb_parameter_group_audit_logs {
    lower(input.Resources[i].Type) == "aws::docdb::dbclusterparametergroup"
    not aws_issue["docdb_parameter_group_audit_logs"]
}

docdb_parameter_group_audit_logs = false {
    aws_issue["docdb_parameter_group_audit_logs"]
}

docdb_parameter_group_audit_logs_err = "Ensure DocDB has audit logs enabled" {
    aws_issue["docdb_parameter_group_audit_logs"]
}

docdb_parameter_group_audit_logs_metadata := {
    "Policy Code": "PR-AWS-CFR-DDB-004",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure DocDB has audit logs enabled",
    "Policy Description": "Ensure DocDB has audit logs enabled, this will export logs in docdb",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbclusterparametergroup.html#aws-resource-docdb-dbclusterparametergroup--examples"
}


#
# PR-AWS-CFR-ATH-001
#

default athena_encryption_disabling_prevent = null

aws_issue["athena_encryption_disabling_prevent"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::athena::workgroup"
    not resource.Properties.WorkGroupConfiguration.EnforceWorkGroupConfiguration
}

aws_issue["athena_encryption_disabling_prevent"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::athena::workgroup"
    lower(resource.Properties.WorkGroupConfiguration.EnforceWorkGroupConfiguration) == "false"
}

athena_encryption_disabling_prevent {
    lower(input.Resources[i].Type) == "aws::athena::workgroup"
    not aws_issue["athena_encryption_disabling_prevent"]
}

athena_encryption_disabling_prevent = false {
    aws_issue["athena_encryption_disabling_prevent"]
}

athena_encryption_disabling_prevent_err = "Ensure to enable EnforceWorkGroupConfiguration for athena workgroup" {
    aws_issue["athena_encryption_disabling_prevent"]
}

athena_encryption_disabling_prevent_metadata := {
    "Policy Code": "PR-AWS-CFR-ATH-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure to enable EnforceWorkGroupConfiguration for athena workgroup",
    "Policy Description": "Athena workgroups support the ability for clients to override configuration options, including encryption requirements. This setting should be disabled to enforce encryption mandates",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html#cfn-docdb-dbcluster-storageencrypted"
}



#
# PR-AWS-CFR-TS-001
#

default timestream_database_encryption = null

aws_issue["timestream_database_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::timestream::database"
    not resource.Properties.KmsKeyId
}

aws_issue["timestream_database_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::timestream::database"
    count(resource.Properties.KmsKeyId) == 0
}

aws_issue["timestream_database_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::timestream::database"
    resource.Properties.KmsKeyId == null
}

timestream_database_encryption {
    lower(input.Resources[i].Type) == "aws::timestream::database"
    not aws_issue["timestream_database_encryption"]
}

timestream_database_encryption = false {
    aws_issue["timestream_database_encryption"]
}

timestream_database_encryption_err = "Ensure Timestream database is encrypted using KMS" {
    aws_issue["timestream_database_encryption"]
}

timestream_database_encryption_metadata := {
    "Policy Code": "PR-AWS-CFR-TS-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure Timestream database is encrypted using KMS",
    "Policy Description": "The timestream databases must be secured with KMS instead of default kms.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-timestream-database.html#cfn-timestream-database-kmskeyid"
}



#
# PR-AWS-CFR-NPT-001
#

default neptune_cluster_logs = null

aws_issue["neptune_cluster_logs"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::neptune::dbcluster"
    not resource.Properties.EnableCloudwatchLogsExports
}

aws_issue["neptune_cluster_logs"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::neptune::dbcluster"
    count(resource.Properties.EnableCloudwatchLogsExports) == 0
}

neptune_cluster_logs {
    lower(input.Resources[i].Type) == "aws::neptune::dbcluster"
    not aws_issue["neptune_cluster_logs"]
}

neptune_cluster_logs = false {
    aws_issue["neptune_cluster_logs"]
}

neptune_cluster_logs_err = "Ensure Neptune logging is enabled" {
    aws_issue["neptune_cluster_logs"]
}

neptune_cluster_logs_metadata := {
    "Policy Code": "PR-AWS-CFR-NPT-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure Neptune logging is enabled",
    "Policy Description": "These access logs can be used to analyze traffic patterns and troubleshoot security and operational issues.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-neptune-dbcluster.html#cfn-neptune-dbcluster-enablecloudwatchlogsexports"
}


#
# PR-AWS-CFR-DD-001
#

default dynamodb_encrypt = null

aws_issue["dynamodb_encrypt"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::dynamodb::table"
    lower(resource.Properties.SSESpecification.SSEEnabled) != "true"
}

aws_bool_issue["dynamodb_encrypt"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::dynamodb::table"
    not resource.Properties.SSESpecification.SSEEnabled
}

dynamodb_encrypt {
    lower(input.Resources[i].Type) == "aws::dynamodb::table"
    not aws_issue["dynamodb_encrypt"]
    not aws_bool_issue["dynamodb_encrypt"]
}

dynamodb_encrypt = false {
    aws_issue["dynamodb_encrypt"]
}

dynamodb_encrypt = false {
    aws_bool_issue["dynamodb_encrypt"]
}

dynamodb_encrypt_err = "AWS DynamoDB encrypted using AWS owned CMK instead of AWS managed CMK" {
    aws_issue["dynamodb_encrypt"]
} else = "AWS DynamoDB encrypted using AWS owned CMK instead of AWS managed CMK" {
    aws_bool_issue["dynamodb_encrypt"]
}

dynamodb_encrypt_metadata := {
    "Policy Code": "PR-AWS-CFR-DD-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS DynamoDB encrypted using AWS owned CMK instead of AWS managed CMK",
    "Policy Description": "This policy identifies the DynamoDB tables that use AWS owned CMK (default ) instead of AWS managed CMK (KMS ) to encrypt data. AWS managed CMK provide additional features such as the ability to view the CMK and key policy, and audit the encryption and decryption of DynamoDB tables.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dynamodb-table.html"
}


#
# PR-AWS-CFR-DD-002
#

default dynamodb_PITR_enable = null

aws_issue["dynamodb_PITR_enable"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::dynamodb::table"
    lower(resource.Properties.PointInTimeRecoverySpecification.PointInTimeRecoveryEnabled) != "true"
}

aws_bool_issue["dynamodb_PITR_enable"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::dynamodb::table"
    not resource.Properties.PointInTimeRecoverySpecification.PointInTimeRecoveryEnabled
}

dynamodb_PITR_enable {
    lower(input.Resources[i].Type) == "aws::dynamodb::table"
    not aws_issue["dynamodb_PITR_enable"]
    not aws_bool_issue["dynamodb_PITR_enable"]
}

dynamodb_PITR_enable = false {
    aws_issue["dynamodb_PITR_enable"]
}

dynamodb_PITR_enable = false {
    aws_bool_issue["dynamodb_PITR_enable"]
}

dynamodb_PITR_enable_err = "Ensure DynamoDB PITR is enabled" {
    aws_issue["dynamodb_PITR_enable"]
} else = "Ensure DynamoDB PITR is enabled" {
    aws_bool_issue["dynamodb_PITR_enable"]
}

dynamodb_PITR_enable_metadata := {
    "Policy Code": "PR-AWS-CFR-DD-002",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure DynamoDB PITR is enabled",
    "Policy Description": "DynamoDB Point-In-Time Recovery (PITR) is an automatic backup service for DynamoDB table data that helps protect your DynamoDB tables from accidental write or delete operations. Once enabled, PITR provides continuous backups that can be controlled using various programmatic parameters. PITR can also be used to restore table data from any point in time during the last 35 days, as well as any incremental backups of DynamoDB tables",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dynamodb-table.html"
}

#
# PR-AWS-CFR-EC-001
#

default cache_failover = null

aws_issue["cache_failover"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticache::replicationgroup"
    lower(resource.Properties.AutomaticFailoverEnabled) == "false"
}

aws_bool_issue["cache_failover"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticache::replicationgroup"
    resource.Properties.AutomaticFailoverEnabled == false
}

cache_failover {
    lower(input.Resources[i].Type) == "aws::elasticache::replicationgroup"
    not aws_issue["cache_failover"]
    not aws_bool_issue["cache_failover"]
}

cache_failover = false {
    aws_issue["cache_failover"]
}

cache_failover = false {
    aws_bool_issue["cache_failover"]
}

cache_failover_err = "AWS ElastiCache Redis cluster with Multi-AZ Automatic Failover feature set to disabled" {
    aws_issue["cache_failover"]
} else = "AWS ElastiCache Redis cluster with Multi-AZ Automatic Failover feature set to disabled" {
    aws_bool_issue["cache_failover"]
}

cache_failover_metadata := {
    "Policy Code": "PR-AWS-CFR-EC-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS ElastiCache Redis cluster with Multi-AZ Automatic Failover feature set to disabled",
    "Policy Description": "This policy identifies ElastiCache Redis clusters which have Multi-AZ Automatic Failover feature set to disabled. It is recommended to enable the Multi-AZ Automatic Failover feature for your Redis Cache cluster, which will improve primary node reachability by providing read replica in case of network connectivity loss or loss of availability in the primary's availability zone for read/write operations._x005F_x000D_ Note: Redis cluster Multi-AZ with automatic failover does not support T1 and T2 cache node types and is only available if the cluster has at least one read replica.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html"
}

#
# PR-AWS-CFR-EC-002
#

default cache_redis_auth = null

aws_attribute_absence["cache_redis_auth"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticache::replicationgroup"
    not resource.Properties.AuthToken
}

aws_issue["cache_redis_auth"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticache::replicationgroup"
    count(resource.Properties.AuthToken) == 0
}

aws_issue["cache_redis_auth"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticache::replicationgroup"
    lower(resource.Properties.TransitEncryptionEnabled) == "false"
}

aws_bool_issue["cache_redis_auth"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticache::replicationgroup"
    not resource.Properties.TransitEncryptionEnabled
}

cache_redis_auth {
    lower(input.Resources[i].Type) == "aws::elasticache::replicationgroup"
    not aws_issue["cache_redis_auth"]
    not aws_bool_issue["cache_redis_auth"]
    not aws_attribute_absence["cache_redis_auth"]
}

cache_redis_auth = false {
    aws_issue["cache_redis_auth"]
}

cache_redis_auth = false {
    aws_bool_issue["cache_redis_auth"]
}

cache_redis_auth = false {
    aws_attribute_absence["cache_redis_auth"]
}

cache_redis_auth_err = "AWS ElastiCache Redis cluster with encryption for data at rest disabled" {
    aws_issue["cache_redis_auth"]
} else = "AWS ElastiCache Redis cluster with encryption for data at rest disabled" {
    aws_bool_issue["cache_redis_auth"]
}

cache_redis_auth_miss_err = "ElastiCache Redis cluster attribute AuthToken missing in the resource" {
    aws_attribute_absence["cache_redis_auth"]
}

cache_redis_auth_metadata := {
    "Policy Code": "PR-AWS-CFR-EC-002",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS ElastiCache Redis cluster with Redis AUTH feature disabled",
    "Policy Description": "This policy identifies ElastiCache Redis clusters which have Redis AUTH feature disabled. Redis AUTH can improve data security by requiring the user to enter a password before they are granted permission to execute Redis commands on a password protected Redis server.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html"
}

#
# PR-AWS-CFR-EC-003
#

default cache_redis_encrypt = null

aws_issue["cache_redis_encrypt"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticache::replicationgroup"
    lower(resource.Properties.AtRestEncryptionEnabled) == "false"
}

aws_bool_issue["cache_redis_encrypt"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticache::replicationgroup"
    not resource.Properties.AtRestEncryptionEnabled
}

cache_redis_encrypt {
    lower(input.Resources[i].Type) == "aws::elasticache::replicationgroup"
    not aws_issue["cache_redis_encrypt"]
    not aws_bool_issue["cache_redis_encrypt"]
}

cache_redis_encrypt = false {
    aws_issue["cache_redis_encrypt"]
}

cache_redis_encrypt = false {
    aws_bool_issue["cache_redis_encrypt"]
}

cache_redis_encrypt_err = "AWS ElastiCache Redis cluster with encryption for data at rest disabled" {
    aws_issue["cache_redis_encrypt"]
} else = "AWS ElastiCache Redis cluster with encryption for data at rest disabled" {
    aws_bool_issue["cache_redis_encrypt"]
}

cache_redis_encrypt_metadata := {
    "Policy Code": "PR-AWS-CFR-EC-003",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS ElastiCache Redis cluster with encryption for data at rest disabled",
    "Policy Description": "This policy identifies ElastiCache Redis clusters which have encryption for data at rest(at-rest) is disabled. It is highly recommended to implement at-rest encryption in order to prevent unauthorized users from reading sensitive data saved to persistent media available on your Redis clusters and their associated cache storage systems.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html"
}

#
# PR-AWS-CFR-EC-004
#

default cache_encrypt = null

aws_issue["cache_encrypt"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticache::replicationgroup"
    lower(resource.Properties.TransitEncryptionEnabled) == "false"
}

aws_bool_issue["cache_encrypt"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticache::replicationgroup"
    not resource.Properties.TransitEncryptionEnabled
}

cache_encrypt {
    lower(input.Resources[i].Type) == "aws::elasticache::replicationgroup"
    not aws_issue["cache_encrypt"]
    not aws_bool_issue["cache_encrypt"]
}

cache_encrypt = false {
    aws_issue["cache_encrypt"]
}

cache_encrypt = false {
    aws_bool_issue["cache_encrypt"]
}


cache_encrypt_err = "AWS ElastiCache Redis cluster with in-transit encryption disabled" {
    aws_issue["cache_encrypt"]
} else = "AWS ElastiCache Redis cluster with in-transit encryption disabled" {
    aws_bool_issue["cache_encrypt"]
}

cache_encrypt_metadata := {
    "Policy Code": "PR-AWS-CFR-EC-004",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS ElastiCache Redis cluster with in-transit encryption disabled",
    "Policy Description": "This policy identifies ElastiCache Redis clusters which have in-transit encryption disabled. It is highly recommended to implement in-transit encryption in order to protect data from unauthorized access as it travels through the network, between clients and cache servers. Enabling data encryption in-transit helps prevent unauthorized users from reading sensitive data between your Redis clusters and their associated cache storage systems.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html"
}


#
# PR-AWS-CFR-EC-005
#

default cache_ksm_key = null

aws_issue["cache_ksm_key"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticache::replicationgroup"
    not resource.Properties.KmsKeyId
}

aws_issue["cache_ksm_key"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticache::replicationgroup"
    not startswith(resource.Properties.KmsKeyId, "arn:")
}

cache_ksm_key {
    lower(input.Resources[i].Type) == "aws::elasticache::replicationgroup"
    not aws_issue["cache_ksm_key"]
}

cache_ksm_key = false {
    aws_issue["cache_ksm_key"]
}

cache_ksm_key_err = "Ensure that ElastiCache replication Group (Redis) are encrypted at rest with customer managed CMK key" {
    aws_issue["cache_ksm_key"]
}

cache_ksm_key_metadata := {
    "Policy Code": "PR-AWS-CFR-EC-005",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure that ElastiCache replication Group (Redis) are encrypted at rest with customer managed CMK key",
    "Policy Description": "This policy identifies ElastiCache Redis clusters which have in-transit encryption disabled. It is highly recommended to implement in-transit encryption in order to protect data from unauthorized access as it travels through the network, between clients and cache servers. Enabling data encryption in-transit helps prevent unauthorized users from reading sensitive data between your Redis clusters and their associated cache storage systems.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-kmskeyid"
}


#
# PR-AWS-CFR-EC-006
#

default cache_default_sg = null

aws_issue["cache_default_sg"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticache::replicationgroup"
    not resource.Properties.CacheSecurityGroupNames
}

aws_issue["cache_default_sg"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticache::replicationgroup"
    count(resource.Properties.CacheSecurityGroupNames) == 0
}

aws_issue["cache_default_sg"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticache::replicationgroup"
    cache_sg := resource.Properties.CacheSecurityGroupNames[_]
    count([c | lower(cache_sg) == "default"; c:=1]) != 0
}

cache_default_sg {
    lower(input.Resources[i].Type) == "aws::elasticache::replicationgroup"
    not aws_issue["cache_default_sg"]
}

cache_default_sg = false {
    aws_issue["cache_default_sg"]
}

cache_default_sg_err = "Ensure 'default' value is not used on Security Group setting for Redis cache engines" {
    aws_issue["cache_default_sg"]
}

cache_default_sg_metadata := {
    "Policy Code": "PR-AWS-CFR-EC-006",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure 'default' value is not used on Security Group setting for Redis cache engines",
    "Policy Description": "Ensure 'default' value is not used on Security Group setting for Redis cache engines",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-cachesubnetgroupname"
}


#
# PR-AWS-CFR-DMS-001
#

default dms_endpoint = null

aws_issue["dms_endpoint"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::dms::endpoint"
    lower(resource.Properties.EngineName) != "s3"
    lower(resource.Properties.SslMode) == "none"
}

aws_issue["dms_endpoint"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::dms::endpoint"
    lower(resource.Properties.EngineName) != "s3"
    not resource.Properties.SslMode
}

dms_endpoint {
    lower(input.Resources[i].Type) == "aws::dms::endpoint"
    not aws_issue["dms_endpoint"]
}

dms_endpoint = false {
    aws_issue["dms_endpoint"]
}

dms_endpoint_err = "Ensure DMS endpoints are supporting SSL configuration" {
    aws_issue["dms_endpoint"]
}

dms_endpoint_metadata := {
    "Policy Code": "PR-AWS-CFR-DMS-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure DMS endpoints are supporting SSL configuration",
    "Policy Description": "This policy identifies Database Migration Service (DMS) endpoints that are not configured with SSL to encrypt connections for source and target endpoints. It is recommended to use SSL connection for source and target endpoints; enforcing SSL connections help protect against 'man in the middle' attacks by encrypting the data stream between endpoint connections.\n\nNOTE: Not all databases use SSL in the same way. An Amazon Redshift endpoint already uses an SSL connection and does not require an SSL connection set up by AWS DMS. So there are some exlcusions included in policy RQL to report only those endpoints which can be configured using DMS SSL feature. \n\nFor more details:\nhttps://docs.aws.amazon.com/dms/latest/userguide/CHAP_Security.html#CHAP_Security.SSL",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.amazonaws.cn/en_us/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-enginename"
}


#
# PR-AWS-CFR-DMS-002
#

default dms_public_access = null

aws_issue["dms_public_access"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::dms::replicationinstance"
    lower(resource.Properties.PubliclyAccessible) != "false"
}

aws_bool_issue["dms_public_access"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::dms::replicationinstance"
    resource.Properties.PubliclyAccessible == true
}

dms_public_access {
    lower(input.Resources[i].Type) == "aws::dms::replicationinstance"
    not aws_issue["dms_public_access"]
    not aws_bool_issue["dms_public_access"]
}

dms_public_access = false {
    aws_issue["dms_public_access"]
}

dms_public_access = false {
    aws_bool_issue["dms_public_access"]
}

dms_public_access_err = "Ensure DMS replication instance is not publicly accessible" {
    aws_issue["dms_public_access"]
} else = "Ensure DMS replication instance is not publicly accessible" {
    aws_bool_issue["dms_public_access"]
}

dms_public_access_metadata := {
    "Policy Code": "PR-AWS-CFR-DMS-002",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure DMS replication instance is not publicly accessible",
    "Policy Description": "Ensure DMS replication instance is not publicly accessible, this might cause sensitive data leak.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationinstance.html#cfn-dms-replicationinstance-publiclyaccessible"
}