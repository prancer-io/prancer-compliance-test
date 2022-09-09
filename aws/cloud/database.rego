package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html
# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-rds-database-instance.html

deprecated_engine_versions := ["10.11","10.12","10.13","11.6","11.7","11.8"]
deprecated_postgres_versions := ["13.2","13.1","12.6","12.5","12.4","12.3","12.2","11.11","11.10","11.9","11.8","11.7","11.6","11.5","11.4","11.3","11.2","11.1","10.16","10.15","10.14","10.13","10.12","10.11","10.10","10.9","10.7","10.6","10.5","10.4","10.3","10.1","9.6.21","9.6.20","9.6.19","9.6.18","9.6.17","9.6.16","9.6.15","9.6.14","9.6.12","9.6.11","9.6.10","9.6.9","9.6.8","9.6.6","9.6.5","9.6.3","9.6.2","9.6.1","9.5","9.4","9.3"]
available_true_choices := ["true", true]
available_false_choices := ["false", false]
has_property(parent_object, target_property) { 
	_ = parent_object[target_property]
}


#
# PR-AWS-CLD-RDS-001
#

default rds_cluster_encrypt = true

rds_cluster_encrypt = false {
    # lower(resource.Type) == "aws::rds::dbcluster"
    DBClusters := input.DBClusters[_]
    not DBClusters.StorageEncrypted
}

rds_cluster_encrypt_err = "AWS RDS DB cluster encryption is disabled" {
    not rds_cluster_encrypt
}

rds_cluster_encrypt_metadata := {
    "Policy Code": "PR-AWS-CLD-RDS-001",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS RDS DB cluster encryption is disabled",
    "Policy Description": "This policy identifies RDS DB clusters for which encryption is disabled. Amazon Aurora encrypted DB clusters provide an additional layer of data protection by securing your data from unauthorized access to the underlying storage. You can use Amazon Aurora encryption to increase data protection of your applications deployed in the cloud, and to fulfill compliance requirements for data-at-rest encryption._x005F_x000D_ NOTE: This policy is applicable only for Aurora DB clusters._x005F_x000D_ https://docs.aws.amazon.com/cli/latest/reference/rds/describe-db-clusters.html",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html"
}

#
# PR-AWS-CLD-RDS-002
#

default rds_public = true

rds_public = false {
    # lower(resource.Type) == "aws::rds::dbinstance"
    DBInstances := input.DBInstances[_]
    DBInstances.PubliclyAccessible == true
}

rds_public_err = "AWS RDS database instance is publicly accessible" {
    not rds_public
}

rds_public_metadata := {
    "Policy Code": "PR-AWS-CLD-RDS-002",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS RDS database instance is publicly accessible",
    "Policy Description": "This policy identifies RDS database instances which are publicly accessible.DB instances should not be publicly accessible to protect the integrety of data.Public accessibility of DB instances can be modified by turning on or off the Public accessibility parameter.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html"
}

#
# PR-AWS-CLD-RDS-003
#

default rds_encrypt_key = true

rds_encrypt_key = false {
    # lower(resource.Type) == "aws::rds::dbinstance"
    DBInstances := input.DBInstances[_]
    not DBInstances.KmsKeyId
}

rds_encrypt_key = false {
    # lower(resource.Type) == "aws::rds::dbinstance"
    DBInstances := input.DBInstances[_]
    count(DBInstances.KmsKeyId) == 0
}

rds_encrypt_key_err = "AWS RDS database not encrypted using Customer Managed Key" {
    not rds_encrypt_key
}

rds_encrypt_key_metadata := {
    "Policy Code": "PR-AWS-CLD-RDS-003",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS RDS database not encrypted using Customer Managed Key",
    "Policy Description": "This policy identifies RDS databases that are encrypted with default KMS keys and not with customer managed keys. As a best practice, use customer managed keys to encrypt the data on your RDS databases and maintain control of your keys and data on sensitive workloads.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html"
}

#
# PR-AWS-CLD-RDS-004
#

default rds_instance_event = true

rds_instance_event = false {
    # lower(resource.Type) == "aws::rds::eventsubscription"
    EventSubscriptionsList := input.EventSubscriptionsList[_]
    EventSubscriptionsList.Enabled == false
    EventSubscriptionsList.SourceType == "db-instance"
}

rds_instance_event_err = "AWS RDS event subscription disabled for DB instance" {
    not rds_instance_event
}

rds_instance_event_metadata := {
    "Policy Code": "PR-AWS-CLD-RDS-004",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS RDS event subscription disabled for DB instance",
    "Policy Description": "This policy identifies RDS event subscriptions for which DB instance event subscription is disabled. You can create an Amazon RDS event notification subscription so that you can be notified when an event occurs for a given DB instance.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html"
}

#
# PR-AWS-CLD-RDS-005
#

default rds_secgroup_event = true

rds_secgroup_event = false {
    # lower(resource.Type) == "aws::rds::eventsubscription"
    EventSubscriptionsList := input.EventSubscriptionsList[_]
    EventSubscriptionsList.Enabled == false
    EventSubscriptionsList.SourceType == "db-security-group"
}

rds_secgroup_event_err = "AWS RDS event subscription disabled for DB security groups" {
    not rds_secgroup_event
}

rds_secgroup_event_metadata := {
    "Policy Code": "PR-AWS-CLD-RDS-005",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS RDS event subscription disabled for DB security groups",
    "Policy Description": "This policy identifies RDS event subscriptions for which DB security groups event subscription is disabled. You can create an Amazon RDS event notification subscription so that you can be notified when an event occurs for given DB security groups.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html"
}

#
# PR-AWS-CLD-RDS-006
#

default rds_encrypt = true

rds_encrypt = false {
    # lower(resource.Type) == "aws::rds::dbinstance"
    DBInstances := input.DBInstances[_]
    not DBInstances.StorageEncrypted
}

rds_encrypt_err = "AWS RDS instance is not encrypted" {
    not rds_encrypt
}

rds_encrypt_metadata := {
    "Policy Code": "PR-AWS-CLD-RDS-006",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS RDS instance is not encrypted",
    "Policy Description": "This policy identifies AWS RDS instances which are not encrypted. Amazon Relational Database Service (Amazon RDS) is a web service that makes it easier to set up and manage databases. Amazon allows customers to turn on encryption for RDS which is recommended for compliance and security reasons.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html"
}

#
# PR-AWS-CLD-RDS-007
#

default rds_multiaz = true

rds_multiaz = false {
    # lower(resource.Type) == "aws::rds::dbinstance"
    DBInstances := input.DBInstances[_]
    lower(DBInstances.Engine) != "aurora"
    lower(DBInstances.Engine) != "sqlserver"
    not DBInstances.MultiAZ
}

rds_multiaz_err = "AWS RDS instance with Multi-Availability Zone disabled" {
    not rds_multiaz
}

rds_multiaz_metadata := {
    "Policy Code": "PR-AWS-CLD-RDS-007",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS RDS instance with Multi-Availability Zone disabled",
    "Policy Description": "This policy identifies RDS instances which have Multi-Availability Zone(Multi-AZ) disabled. When RDS DB instance is enabled with Multi-AZ, RDS automatically creates a primary DB Instance and synchronously replicates the data to a standby instance in a different availability zone. These Multi-AZ deployments will improve primary node reachability by providing read replica in case of network connectivity loss or loss of availability in the primaryâ€™s availability zone for read/write operations, so by making them the best fit for production database workloads.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html"
}

#
# PR-AWS-CLD-RDS-008
#

default rds_snapshot = true

rds_snapshot = false {
    # lower(resource.Type) == "aws::rds::dbinstance"
    DBInstances := input.DBInstances[_]
    not DBInstances.CopyTagsToSnapshot
}

rds_snapshot_err = "AWS RDS instance with copy tags to snapshots disabled" {
    not rds_snapshot
}

rds_snapshot_metadata := {
    "Policy Code": "PR-AWS-CLD-RDS-008",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS RDS instance with copy tags to snapshots disabled",
    "Policy Description": "This policy identifies RDS instances which have copy tags to snapshots disabled. Copy tags to snapshots copies all the user-defined tags from the DB instance to snapshots. Copying tags allow you to add metadata and apply access policies to your Amazon RDS resources.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html"
}

#
# PR-AWS-CLD-RDS-009
#

default rds_backup = true

rds_backup = false {
    # lower(resource.Type) == "aws::rds::dbinstance"
    DBInstances := input.DBInstances[_]
    not DBInstances.BackupRetentionPeriod
}

rds_backup = false {
    # lower(resource.Type) == "aws::rds::dbinstance"
    DBInstances := input.DBInstances[_]
    to_number(DBInstances.BackupRetentionPeriod) == 0
}

rds_backup_err = "AWS RDS instance without Automatic Backup setting" {
    not rds_backup
}


rds_backup_metadata := {
    "Policy Code": "PR-AWS-CLD-RDS-009",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS RDS instance without Automatic Backup setting",
    "Policy Description": "This policy identifies RDS instances which are not set with the Automatic Backup setting. If Automatic Backup is set, RDS creates a storage volume snapshot of your DB instance, backing up the entire DB instance and not just individual databases which provide for point-in-time recovery. The automatic backup will happen during the specified backup window time and keeps the backups for a limited period of time as defined in the retention period. It is recommended to set Automatic backups for your critical RDS servers that will help in the data restoration process.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html"
}

#
# PR-AWS-CLD-RDS-010
#

default rds_upgrade = true


rds_upgrade = false {
    # lower(resource.Type) == "aws::rds::dbinstance"
    DBInstances := input.DBInstances[_]
    not DBInstances.AutoMinorVersionUpgrade
}

rds_upgrade_err = "AWS RDS minor upgrades not enabled" {
    not rds_upgrade
}

rds_upgrade_metadata := {
    "Policy Code": "PR-AWS-CLD-RDS-010",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS RDS minor upgrades not enabled",
    "Policy Description": "When Amazon Relational Database Service (Amazon RDS) supports a new version of a database engine, you can upgrade your DB instances to the new version. There are two kinds of upgrades: major version upgrades and minor version upgrades. Minor upgrades helps maintain a secure and stable RDS with minimal impact on the application. For this reason, we recommend that your automatic minor upgrade is enabled. Minor version upgrades only occur automatically if a minor upgrade replaces an unsafe version, such as a minor upgrade that contains bug fixes for a previous version.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html"
}

#
# PR-AWS-CLD-RDS-011
#

default rds_retention = true

rds_retention = false {
    # lower(resource.Type) == "aws::rds::dbinstance"
    DBInstances := input.DBInstances[_]
    not DBInstances.BackupRetentionPeriod
}

rds_retention = false {
    # lower(resource.Type) == "aws::rds::dbinstance"
    DBInstances := input.DBInstances[_]
    to_number(DBInstances.BackupRetentionPeriod) < 7
}

rds_retention_err = "AWS RDS retention policy less than 7 days" {
    not rds_retention
}

rds_retention_metadata := {
    "Policy Code": "PR-AWS-CLD-RDS-011",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS RDS retention policy less than 7 days",
    "Policy Description": "RDS Retention Policies for Backups are an important part of your DR/BCP strategy. Recovering data from catastrophic failures, malicious attacks, or corruption often requires a several day window of potentially good backup material to leverage. As such, the best practice is to ensure your RDS clusters are retaining at least 7 days of backups, if not more (up to a maximum of 35).",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html"
}


#
# PR-AWS-CLD-RDS-012
#

default rds_cluster_retention = true

rds_cluster_retention = false {
    # lower(resource.Type) == "aws::rds::dbcluster"
    DBClusters := input.DBClusters[_]
    not DBClusters.BackupRetentionPeriod
}

rds_cluster_retention = false {
    # lower(resource.Type) == "aws::rds::dbcluster"
    DBClusters := input.DBClusters[_]
    to_number(DBClusters.BackupRetentionPeriod) < 7
}

rds_cluster_retention_err = "AWS RDS retention policy less than 7 days" {
    not rds_cluster_retention
}

rds_cluster_retention_metadata := {
    "Policy Code": "PR-AWS-CLD-RDS-012",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS RDS cluster retention policy less than 7 days",
    "Policy Description": "RDS cluster Retention Policies for Backups are an important part of your DR/BCP strategy. Recovering data from catastrophic failures, malicious attacks, or corruption often requires a several day window of potentially good backup material to leverage. As such, the best practice is to ensure your RDS clusters are retaining at least 7 days of backups, if not more (up to a maximum of 35).",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html"
}


#
# PR-AWS-CLD-RDS-013
#

default rds_cluster_deletion_protection = true

rds_cluster_deletion_protection = false {
    # lower(resource.Type) == "aws::rds::dbcluster"
    DBClusters := input.DBClusters[_]
    not DBClusters.DeletionProtection
}

rds_cluster_deletion_protection_err = "Ensure RDS clusters and instances have deletion protection enabled" {
    not rds_cluster_deletion_protection
}

rds_cluster_deletion_protection_metadata := {
    "Policy Code": "PR-AWS-CLD-RDS-013",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure RDS clusters and instances have deletion protection enabled",
    "Policy Description": "This rule Checks if an Amazon Relational Database Service (Amazon RDS) cluster has deletion protection enabled",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html"
}


#
# PR-AWS-CLD-RDS-014
#

default rds_pgaudit_enable = true

rds_pgaudit_enable = false {
    # lower(resource.Type) == "aws::rds::dbparametergroup"
    Parameters := input.Parameters[_]
    lower(Parameters.ParameterName) == "pgaudit.role"
    lower(Parameters.ParameterValue) != "rds_pgaudit"
}

rds_pgaudit_enable = false {
    # lower(resource.Type) == "aws::rds::dbparametergroup"
    Parameters := input.Parameters[_]
    lower(Parameters.ParameterName) == "pgaudit.role"
    not Parameters.ParameterValue
}

rds_pgaudit_enable = false {
    # lower(resource.Type) == "aws::rds::dbparametergroup"
    count([c| lower(input.Parameters[_].ParameterName) == "pgaudit.role"; c:=1]) == 0
}

rds_pgaudit_enable = false {
    # lower(resource.Type) == "aws::rds::dbparametergroup"
    count(input.Parameters) == 0
}

rds_pgaudit_enable = false {
    # lower(resource.Type) == "aws::rds::dbparametergroup"
    not input.Parameters
}

rds_pgaudit_enable_err = "Ensure PGAudit is enabled on RDS Postgres instances" {
    not rds_pgaudit_enable
}

rds_pgaudit_enable_metadata := {
    "Policy Code": "PR-AWS-CLD-RDS-014",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure PGAudit is enabled on RDS Postgres instances",
    "Policy Description": "Postgres database instances can be enabled for auditing with PGAudit, the PostgresSQL Audit Extension. With PGAudit enabled you will be able to audit any database, its roles, relations, or columns.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-rds-dbparametergroup.html#cfn-rds-dbparametergroup-parameters"
}

#
# PR-AWS-CLD-RDS-015
#

default rds_global_cluster_encrypt = true

rds_global_cluster_encrypt = false {
    # lower(resource.Type) == "aws::rds::globalcluster"
    GlobalClusters := input.GlobalClusters[_]
    not GlobalClusters.StorageEncrypted
}

rds_global_cluster_encrypt_err = "AWS RDS Global DB cluster encryption is disabled" {
    not rds_global_cluster_encrypt
}

rds_global_cluster_encrypt_metadata := {
    "Policy Code": "PR-AWS-CLD-RDS-015",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS RDS Global DB cluster encryption is disabled",
    "Policy Description": "This policy identifies RDS Global DB clusters for which encryption is disabled. Amazon Aurora encrypted Global DB clusters provide an additional layer of data protection by securing your data from unauthorized access to the underlying storage. You can use Amazon Aurora encryption to increase data protection of your applications deployed in the cloud, and to fulfill compliance requirements",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-globalcluster.html"
}

#
# PR-AWS-CLD-RDS-016
#

default cluster_iam_authenticate = true

cluster_iam_authenticate = false {
    # lower(resource.Type) == "aws::rds::dbcluster"
    DBClusters := input.DBClusters[_]
    not DBClusters.EnableIAMDatabaseAuthentication
}

cluster_iam_authenticate_err = "Ensure RDS cluster has IAM authentication enabled" {
    not cluster_iam_authenticate
}

cluster_iam_authenticate_metadata := {
    "Policy Code": "PR-AWS-CLD-RDS-016",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure RDS cluster has IAM authentication enabled",
    "Policy Description": "Ensure IAM Database Authentication feature is enabled in order to use AWS Identity and Access Management (IAM) service to manage database access to your Amazon RDS MySQL and PostgreSQL instances. With this feature enabled, you don't have to use a password when you connect to your MySQL/PostgreSQL database instances, instead you use an authentication token",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html#cfn-rds-dbcluster-enableiamdatabaseauthentication"
}

#
# PR-AWS-CLD-RDS-017
#

default db_instance_iam_authenticate = true

db_instance_iam_authenticate = false {
    # lower(resource.Type) == "aws::rds::dbinstance"
    DBInstances := input.DBInstances[_]
    not DBInstances.EnableIAMDatabaseAuthentication
}

db_instance_iam_authenticate_err = "Ensure RDS instance has IAM authentication enabled" {
    not db_instance_iam_authenticate
}

db_instance_iam_authenticate_metadata := {
    "Policy Code": "PR-AWS-CLD-RDS-017",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure RDS instace has IAM authentication enabled",
    "Policy Description": "Ensure IAM Database Authentication feature is enabled in order to use AWS Identity and Access Management (IAM) service to manage database access to your Amazon RDS MySQL and PostgreSQL instances. With this feature enabled, you don't have to use a password when you connect to your MySQL/PostgreSQL database instances, instead you use an authentication token",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-rds-database-instance.html#cfn-rds-dbinstance-enableiamdatabaseauthentication"
}


#
# PR-AWS-CLD-RDS-018
#

default db_instance_cloudwatch_logs = true

db_instance_cloudwatch_logs = false {
    # lower(resource.Type) == "aws::rds::dbinstance"
    DBInstances := input.DBInstances[_]
    count(DBInstances.EnabledCloudwatchLogsExports) == 0
}

db_instance_cloudwatch_logs = false {
    # lower(resource.Type) == "aws::rds::dbinstance"
    DBInstances := input.DBInstances[_]
    not DBInstances.EnabledCloudwatchLogsExports
}

db_instance_cloudwatch_logs_err = "Ensure respective logs of Amazon RDS instance are enabled" {
    not db_instance_cloudwatch_logs
}

db_instance_cloudwatch_logs_metadata := {
    "Policy Code": "PR-AWS-CLD-RDS-018",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure respective logs of Amazon RDS instance are enabled",
    "Policy Description": "Use CloudWatch logging types for Amazon Relational Database Service (Amazon RDS) instances",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-rds-database-instance.html#cfn-rds-dbinstance-enablecloudwatchlogsexports"
}



#
# PR-AWS-CLD-RDS-019
#

default db_instance_monitor = true

db_instance_monitor = false {
    # lower(resource.Type) == "aws::rds::dbinstance"
    DBInstances := input.DBInstances[_]
    not DBInstances.MonitoringInterval
}

db_instance_monitor_err = "Enhanced monitoring for Amazon RDS instances is enabled" {
    not db_instance_monitor
}

db_instance_monitor_metadata := {
    "Policy Code": "PR-AWS-CLD-RDS-019",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Enhanced monitoring for Amazon RDS instances is enabled",
    "Policy Description": "This New Relic integration allows you to monitor and alert on RDS Enhanced Monitoring. You can use integration data and alerts to monitor the DB processes and identify potential trouble spots as well as to profile the DB allowing you to improve and optimize their response and cost",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-rds-database-instance.html#cfn-rds-dbinstance-monitoringinterval"
}

#
# PR-AWS-CLD-RDS-021
#

default db_instance_engine_version = true

db_instance_engine_version = false {
    # lower(resource.Type) == "aws::rds::dbinstance"
    DBInstances := input.DBInstances[_]
    lower(DBInstances.Engine) == "aurora-postgresql"
    lower(DBInstances.EngineVersion) == deprecated_engine_versions[_]
}

db_instance_engine_version_err = "Ensure RDS instances do not use a deprecated version of Aurora-PostgreSQL." {
    not db_instance_engine_version
}

db_instance_engine_version_metadata := {
    "Policy Code": "PR-AWS-CLD-RDS-021",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure RDS instances do not use a deprecated version of Aurora-PostgreSQL.",
    "Policy Description": "AWS Aurora PostgreSQL which is exposed to local file read vulnerability. It is highly recommended to upgrade AWS Aurora PostgreSQL to the latest version.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-rds-database-instance.html#aws-properties-rds-database-instance--examples"
}

#
# PR-AWS-CLD-RDS-022
#

default db_cluster_engine_version = true

db_cluster_engine_version = false {
    # lower(resource.Type) == "aws::rds::dbcluster"
    DBClusters := input.DBClusters[_]
    lower(DBClusters.Engine) == "aurora-postgresql"
    lower(DBClusters.EngineVersion) == deprecated_engine_versions[_]
}

db_cluster_engine_version_err = "Ensure RDS cluster do not use a deprecated version of Aurora-PostgreSQL." {
    not db_cluster_engine_version
}

db_cluster_engine_version_metadata := {
    "Policy Code": "PR-AWS-CLD-RDS-022",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure RDS cluster do not use a deprecated version of Aurora-PostgreSQL.",
    "Policy Description": "AWS Aurora PostgreSQL which is exposed to local file read vulnerability. It is highly recommended to upgrade AWS Aurora PostgreSQL to the latest version.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html#aws-resource-rds-dbcluster--examples"
}

#
# PR-AWS-CLD-RDS-023
#

default db_instance_approved_postgres_version = true

db_instance_approved_postgres_version = false {
    # lower(resource.Type) == "aws::rds::dbinstance"
    DBInstances := input.DBInstances[_]
    lower(DBInstances.Engine) == "postgres"
    lower(DBInstances.EngineVersion) == deprecated_postgres_versions[_]
}

db_instance_approved_postgres_version_err = "Ensure RDS instances do not use a deprecated version of PostgreSQL." {
    not db_instance_approved_postgres_version
}

db_instance_approved_postgres_version_metadata := {
    "Policy Code": "PR-AWS-CLD-RDS-023",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure RDS instances do not use a deprecated version of PostgreSQL.",
    "Policy Description": "AWS RDS PostgreSQL which is exposed to local file read vulnerability. It is highly recommended to upgrade AWS RDS PostgreSQL to the latest version.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-rds-database-instance.html#aws-properties-rds-database-instance--examples"
}

#
# PR-AWS-CLD-RDS-024
#

default db_cluster_approved_postgres_version = true

db_cluster_approved_postgres_version = false {
    # lower(resource.Type) == "aws::rds::dbcluster"
    DBClusters := input.DBClusters[_]
    lower(DBClusters.Engine) == "postgres"
    lower(DBClusters.EngineVersion) == deprecated_postgres_versions[_]
}

db_cluster_approved_postgres_version_err = "Ensure RDS dbcluster do not use a deprecated version of PostgreSQL." {
    not db_cluster_approved_postgres_version
}

db_cluster_approved_postgres_version_metadata := {
    "Policy Code": "PR-AWS-CLD-RDS-024",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure RDS dbcluster do not use a deprecated version of PostgreSQL.",
    "Policy Description": "AWS RDS PostgreSQL which is exposed to local file read vulnerability. It is highly recommended to upgrade AWS RDS PostgreSQL to the latest version.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html#aws-resource-rds-dbcluster--examples"
}

#
# PR-AWS-CLD-RDS-025
#

default db_snapshot_is_encrypted = true

db_snapshot_is_encrypted = false {
    DBSnapshot := input.DBSnapshots[_]
    lower(DBSnapshot.Status) == "available"
    lower(DBSnapshot.Encrypted) == available_false_choices[_]
}

db_snapshot_is_encrypted_err = "Ensure AWS RDS DB snapshot is encrypted." {
    not db_snapshot_is_encrypted
}

db_snapshot_is_encrypted_metadata := {
    "Policy Code": "PR-AWS-CLD-RDS-025",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS RDS DB snapshot is encrypted.",
    "Policy Description": "It identifies AWS RDS DB (Relational Database Service Database) cluster snapshots which are not encrypted. It is highly recommended to implement encryption at rest when you are working with production data that have sensitive information, to protect from unauthorized access.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/rds.html#RDS.Client.describe_db_snapshots"
}

#
# PR-AWS-CLD-RDS-026
#

default rds_snapshot_with_access = true

rds_snapshot_with_access = false {
    DBSnapshotAttribute := input.DBSnapshotAttributesResult.DBSnapshotAttributes[_]
    lower(DBSnapshotAttribute.AttributeName) == "restore"
    count(DBSnapshotAttribute.AttributeValues[_]) != 0
}

rds_snapshot_with_access_err = "Ensure AWS RDS Snapshot with access for only monitored cloud accounts." {
    not rds_snapshot_with_access
}

rds_snapshot_with_access_metadata := {
    "Policy Code": "PR-AWS-CLD-RDS-026",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS RDS Snapshot with access for only monitored cloud accounts.",
    "Policy Description": "It identifies RDS snapshots with access for unmonitored cloud accounts.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/rds.html#RDS.Client.describe_db_snapshot_attributes"
}

#
# PR-AWS-CLD-RDS-027
# aws::rds::dbinstance
#

default rds_iam_database_auth = true

rds_iam_database_auth = false {
    DBInstance := input.DBInstances[_]
    not DBInstance.IAMDatabaseAuthenticationEnabled
}

rds_iam_database_auth_err = "Ensure AWS RDS DB authentication is only enabled via IAM" {
    not rds_iam_database_auth
}

rds_iam_database_auth_metadata := {
    "Policy Code": "PR-AWS-CLD-RDS-027",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS RDS DB authentication is only enabled via IAM",
    "Policy Description": "This policy checks RDS DB instances which are not configured with IAM based authentication and using any hardcoded credentials.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-rds-database-instance.html"
}

#
# PR-AWS-CLD-RDS-028
# aws::rds::dbcluster
#

default rds_cluster_backup_retention = true

rds_cluster_backup_retention = false {
    DBClusters := input.DBClusters[_]
    not DBClusters.BackupRetentionPeriod
}

rds_cluster_backup_retention = false {
    DBClusters := input.DBClusters[_]
    to_number(DBClusters.BackupRetentionPeriod) < 30
}

rds_cluster_backup_retention_err = "Ensure AWS RDS Cluster has setup backup retention period of at least 30 days" {
    not rds_cluster_backup_retention
}

rds_cluster_backup_retention_metadata := {
    "Policy Code": "PR-AWS-CLD-RDS-028",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS RDS Cluster has setup backup retention period of at least 30 days",
    "Policy Description": "This policy checks that backup retention period for RDS DB is firm approved.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html"
}

#
# PR-AWS-CLD-RDS-029
# aws::rds::dbinstance

default db_instance_deletion_protection = true

db_instance_deletion_protection = false {
    DBInstance := input.DBInstances[_]
    lower(DBInstance.DeletionProtection) == available_false_choices[_]
}

db_instance_deletion_protection_err = "Ensure AWS RDS DB instance has deletion protection enabled." {
    not db_instance_deletion_protection
}

db_instance_deletion_protection_metadata := {
    "Policy Code": "PR-AWS-CLD-RDS-029",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS RDS DB instance has deletion protection enabled.",
    "Policy Description": "It is to check that deletion protection in enabled at RDS DB level in order to protect the DB instance from accidental deletion.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/rds.html#RDS.Client.describe_db_instances"
}

#
# PR-AWS-CLD-RDS-030
# aws::rds::dbinstance

default db_instance_backup_retention_period = true

db_instance_backup_retention_period = false {
    DBInstance := input.DBInstances[_]
    to_number(DBInstance.BackupRetentionPeriod) < 30
}

db_instance_backup_retention_period = false {
    DBInstance := input.DBInstances[_]
    not DBInstance.BackupRetentionPeriod
}


db_instance_backup_retention_period_err = "Ensure RDS DB instance has setup backup retention period of at least 30 days." {
    not db_instance_backup_retention_period
}

db_instance_backup_retention_period_metadata := {
    "Policy Code": "PR-AWS-CLD-RDS-030",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure RDS DB instance has setup backup retention period of at least 30 days.",
    "Policy Description": "This is to check that backup retention period for RDS DB is firm approved.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/rds.html#RDS.Client.describe_db_instances"
}


#
# PR-AWS-CLD-RDS-031
# aws::rds::dbcluster
# AWS::KMS::Key

default rds_cluster_encrypt_cmk = true

rds_cluster_encrypt_cmk = false {
    X := input.TEST_RDS_02[_]
    DBCluster := X.DBClusters[_]
    DBCluster.StorageEncrypted == true
    Y := input.TEST_KMS[_]
    DBCluster.KmsKeyId == Y.KeyMetadata.Arn
    Y.KeyMetadata.KeyManager != "CUSTOMER"
}

rds_cluster_encrypt_cmk_err = "Ensure AWS RDS DB cluster is not encrypted using default KMS key instead of CMK." {
    not rds_cluster_encrypt_cmk
}

rds_cluster_encrypt_cmk_metadata := {
    "Policy Code": "PR-AWS-CLD-RDS-031",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS RDS DB cluster is not encrypted using default KMS key instead of CMK.",
    "Policy Description": "It identifies RDS DB(Relational Database Service Database) clusters which are encrypted using default KMS key instead of CMK (Customer Master Key). As a security best practice CMK should be used instead of default KMS key for encryption to gain the ability to rotate the key according to your own policies, delete the key, and control access to the key via KMS policies and IAM policies.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/rds.html#RDS.Client.describe_db_clusters"
}


#
# PR-AWS-CLD-DAX-001
#

default dax_encrypt = true

dax_encrypt = false {
    # lower(resource.Type) == "aws::dax::cluster"
    Clusters := input.Clusters[_]
    not Clusters.SSEDescription.Status
}

dax_encrypt = false {
    # lower(resource.Type) == "aws::dax::cluster"
    Clusters := input.Clusters[_]
    lower(Clusters.SSEDescription.Status) != "enabling"
    lower(Clusters.SSEDescription.Status) != "enabled"
}

dax_encrypt_err = "Ensure DAX is securely encrypted at rest" {
    not dax_encrypt
}

dax_encrypt_metadata := {
    "Policy Code": "PR-AWS-CLD-DAX-001",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure DAX is securely encrypted at rest",
    "Policy Description": "Amazon DynamoDB Accelerator (DAX) encryption at rest provides an additional layer of data protection, helping secure your data from unauthorized access to underlying storage. With encryption at rest the data persisted by DAX on disk is encrypted using 256-bit Advanced Encryption Standard (AES-256). DAX writes data to disk as part of propagating changes from the primary node to read replicas. DAX encryption at rest automatically integrates with AWS KMS for managing the single service default key used to encrypt clusters.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dax-cluster-ssespecification.html"
}

#
# PR-AWS-CLD-DAX-002
#

default dax_cluster_endpoint_encrypt_at_rest = true

dax_cluster_endpoint_encrypt_at_rest = false {
    # lower(resource.Type) == "aws::dax::cluster"
    Clusters := input.Clusters[_]
    lower(Clusters.ClusterEndpointEncryptionType) != "tls"
}

dax_cluster_endpoint_encrypt_at_rest = false {
    # lower(resource.Type) == "aws::dax::cluster"
    Clusters := input.Clusters[_]
    not Clusters.ClusterEndpointEncryptionType
}

dax_cluster_endpoint_encrypt_at_rest_err = "Ensure AWS DAX data is encrypted in transit" {
    not dax_cluster_endpoint_encrypt_at_rest
}

dax_cluster_endpoint_encrypt_at_rest_metadata := {
    "Policy Code": "PR-AWS-CLD-DAX-002",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS DAX data is encrypted in transit",
    "Policy Description": "This control is to check that the communication between the application and DAX is always encrypted",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/cli/latest/reference/dax/describe-clusters.html"
}


#
# PR-AWS-CLD-DAX-003
# aws::dax::cluster
# AWS::KMS::Key

default dax_gs_managed_key = true

dax_gs_managed_key = false {
    X := input.TEST_DAX[_]
    Cluster := X.Clusters[_]
    Y := input.TEST_KMS[_]
    Cluster.SSEDescription.KMSMasterKeyArn == Y.KeyMetadata.Arn
    Y.KeyMetadata.KeyManager != "CUSTOMER"
}

dax_gs_managed_key_err = "Ensure for AWS DAX GS-managed key is used in encryption." {
    not dax_gs_managed_key
}

dax_gs_managed_key_metadata := {
    "Policy Code": "PR-AWS-CLD-DAX-003",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure for AWS DAX GS-managed key is used in encryption.",
    "Policy Description": "It is to check that data at rest encryption has used firm managed CMK.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/dax.html#DAX.Client.describe_clusters"
}


#
# PR-AWS-CLD-QLDB-001
#

default qldb_permission_mode = true

qldb_permission_mode = false {
    # lower(resource.Type) == "aws::qldb::ledger"
    lower(input.PermissionsMode) != "standard"
}

qldb_permission_mode_err = "Ensure QLDB ledger permissions mode is set to STANDARD" {
    not qldb_permission_mode
}

qldb_permission_mode_metadata := {
    "Policy Code": "PR-AWS-CLD-QLDB-001",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure QLDB ledger permissions mode is set to STANDARD",
    "Policy Description": "In Amazon Quantum Ledger Database define PermissionsMode value to STANDARD permissions mode that enables access control with finer granularity for ledgers, tables, and PartiQL commands",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-qldb-ledger.html#cfn-qldb-ledger-permissionsmode"
}



#
# PR-AWS-CLD-DDB-001
#

default docdb_cluster_encrypt = true

docdb_cluster_encrypt = false {
    # lower(resource.Type) == "aws::docdb::dbcluster"
    DBClusters := input.DBClusters[_]
    not DBClusters.StorageEncrypted
}

docdb_cluster_encrypt_err = "Ensure DocumentDB cluster is encrypted at rest" {
    not docdb_cluster_encrypt
}

docdb_cluster_encrypt_metadata := {
    "Policy Code": "PR-AWS-CLD-DDB-001",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure DocumentDB cluster is encrypted at rest",
    "Policy Description": "Ensure that encryption is enabled for your AWS DocumentDB (with MongoDB compatibility) clusters for additional data security and in order to meet compliance requirements for data-at-rest encryption",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html#cfn-docdb-dbcluster-storageencrypted"
}


#
# PR-AWS-CLD-DDB-002
#

default docdb_cluster_logs = true

docdb_cluster_logs = false {
    # lower(resource.Type) == "aws::docdb::dbcluster"
    DBClusters := input.DBClusters[_]
    not DBClusters.EnabledCloudwatchLogsExports
}


docdb_cluster_logs = false {
    # lower(resource.Type) == "aws::docdb::dbcluster"
    DBClusters := input.DBClusters[_]
    count(DBClusters.EnabledCloudwatchLogsExports) == 0
}

docdb_cluster_logs_err = "Ensure AWS DocumentDB logging is enabled" {
    not docdb_cluster_logs
}

docdb_cluster_logs_metadata := {
    "Policy Code": "PR-AWS-CLD-DDB-002",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS DocumentDB logging is enabled",
    "Policy Description": "The events recorded by the AWS DocumentDB audit logs include: successful and failed authentication attempts, creating indexes or dropping a collection in a database within the DocumentDB cluster.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html#cfn-docdb-dbcluster-enablecloudwatchlogsexports"
}

#
# PR-AWS-CLD-DDB-003
#

default docdb_parameter_group_tls_enable = true

docdb_parameter_group_tls_enable = false {
    # lower(resource.Type) == "aws::docdb::dbclusterparametergroup"
    not input.Parameters
}

docdb_parameter_group_tls_enable = false {
    # lower(resource.Type) == "aws::docdb::dbclusterparametergroup"
    count(input.Parameters) == 0
}

docdb_parameter_group_tls_enable = false {
    # lower(resource.Type) == "aws::docdb::dbclusterparametergroup"
    count([c | input.Parameters[_].ParameterName == "tls"; c:=1]) == 0
}

docdb_parameter_group_tls_enable = false {
    # lower(resource.Type) == "aws::docdb::dbclusterparametergroup"
    Parameters := input.Parameters[_]
    lower(Parameters.ParameterName) == "tls"
    lower(Parameters.ParameterValue) != "enabled"
}

docdb_parameter_group_tls_enable_err = "Ensure DocDB ParameterGroup has TLS enable" {
    not docdb_parameter_group_tls_enable
}

docdb_parameter_group_tls_enable_metadata := {
    "Policy Code": "PR-AWS-CLD-DDB-003",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure DocDB ParameterGroup has TLS enable",
    "Policy Description": "TLS can be used to encrypt the connection between an application and a DocDB cluster. By default, encryption in transit is enabled for newly created clusters. It can optionally be disabled when the cluster is created, or at a later time. When enabled, secure connections using TLS are required to connect to the cluster.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbclusterparametergroup.html#cfn-docdb-dbclusterparametergroup-parameters"
}


#
# PR-AWS-CLD-DDB-004
#

default docdb_parameter_group_audit_logs = true

docdb_parameter_group_audit_logs = false {
    # lower(resource.Type) == "aws::docdb::dbclusterparametergroup"
    not input.Parameters
}

docdb_parameter_group_audit_logs = false {
    # lower(resource.Type) == "aws::docdb::dbclusterparametergroup"
    count(input.Parameters) == 0
}

docdb_parameter_group_audit_logs = false {
    # lower(resource.Type) == "aws::docdb::dbclusterparametergroup"
    count([c | input.Parameters[_].ParameterName == "audit_logs"; c:=1]) == 0
}

docdb_parameter_group_audit_logs = false {
    # lower(resource.Type) == "aws::docdb::dbclusterparametergroup"
    Parameters := input.Parameters[_]
    lower(Parameters.ParameterName) == "audit_logs"
    lower(Parameters.ParameterValue) != "enabled"
}

docdb_parameter_group_audit_logs_err = "Ensure DocDB has audit logs enabled" {
    not docdb_parameter_group_audit_logs
}

docdb_parameter_group_audit_logs_metadata := {
    "Policy Code": "PR-AWS-CLD-DDB-004",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure DocDB has audit logs enabled",
    "Policy Description": "Ensure DocDB has audit logs enabled, this will export logs in docdb",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbclusterparametergroup.html#aws-resource-docdb-dbclusterparametergroup--examples"
}


#
# PR-AWS-CLD-ATH-001
#

default athena_encryption_disabling_prevent = true

athena_encryption_disabling_prevent = false {
    # lower(resource.Type) == "aws::athena::workgroup"
    not input.WorkGroup.Configuration.EnforceWorkGroupConfiguration
}

athena_encryption_disabling_prevent_err = "Ensure to enable EnforceWorkGroupConfiguration for athena workgroup" {
    not athena_encryption_disabling_prevent
}

athena_encryption_disabling_prevent_metadata := {
    "Policy Code": "PR-AWS-CLD-ATH-001",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure to enable EnforceWorkGroupConfiguration for athena workgroup",
    "Policy Description": "Athena workgroups support the ability for clients to override configuration options, including encryption requirements. This setting should be disabled to enforce encryption mandates",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html#cfn-docdb-dbcluster-storageencrypted"
}

#
# PR-AWS-CLD-ATH-002
#

default athena_logging_is_enabled = true

athena_logging_is_enabled = false {
    # lower(resource.Type) == "aws::athena::workgroup"
    input.WorkGroup.Configuration.PublishCloudWatchMetricsEnabled == available_true_choices[_]
}

athena_logging_is_enabled_err = "Ensure Athena logging is enabled for athena workgroup." {
    not athena_logging_is_enabled
}

athena_logging_is_enabled_metadata := {
    "Policy Code": "PR-AWS-CLD-ATH-002",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure Athena logging is enabled for athena workgroup.",
    "Policy Description": "It checks if logging is enabled for Athena to detect incidents, receive alerts when incidents occur, and respond to them. logs can be configured via CloudTrail, CloudWatch events and Quicksights for visualization.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/athena.html#Athena.Client.get_work_group"
}


#
# PR-AWS-CLD-TS-001
#

default timestream_database_encryption = true

timestream_database_encryption = false {
    # lower(resource.Type) == "aws::timestream::database"
    Databases := input.Databases[_]
    not Databases.KmsKeyId
}

timestream_database_encryption = false {
    # lower(resource.Type) == "aws::timestream::database"
    Databases := input.Databases[_]
    count(Databases.KmsKeyId) == 0
}

timestream_database_encryption = false {
    # lower(resource.Type) == "aws::timestream::database"
    Databases := input.Databases[_]
    Databases.KmsKeyId == null
}

timestream_database_encryption_err = "Ensure Timestream database is encrypted using KMS" {
    not timestream_database_encryption
}

timestream_database_encryption_metadata := {
    "Policy Code": "PR-AWS-CLD-TS-001",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure Timestream database is encrypted using KMS",
    "Policy Description": "The timestream databases must be secured with KMS instead of default kms.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-timestream-database.html#cfn-timestream-database-kmskeyid"
}



#
# PR-AWS-CLD-NPT-001
#

default neptune_cluster_logs = true

neptune_cluster_logs = false {
    # lower(resource.Type) == "aws::neptune::dbcluster"
    DBClusters := input.DBClusters[_]
    not DBClusters.EnabledCloudwatchLogsExports
}

neptune_cluster_logs = false {
    # lower(resource.Type) == "aws::neptune::dbcluster"
    DBClusters := input.DBClusters[_]
    count(DBClusters.EnabledCloudwatchLogsExports) == 0
}

neptune_cluster_logs_err = "Ensure Neptune logging is enabled" {
    not neptune_cluster_logs
}

neptune_cluster_logs_metadata := {
    "Policy Code": "PR-AWS-CLD-NPT-001",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure Neptune logging is enabled",
    "Policy Description": "These access logs can be used to analyze traffic patterns and troubleshoot security and operational issues.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-neptune-dbcluster.html#cfn-neptune-dbcluster-EnableCloudwatchLogsExports"
}


#
# PR-AWS-CLD-DD-001
#

default dynamodb_encrypt = true

dynamodb_encrypt = false {
    # lower(resource.Type) == "aws::dynamodb::table"
    lower(input.Table.SSEDescription.Status) != "enabling"
    lower(input.Table.SSEDescription.Status) != "enabled"
}

dynamodb_encrypt = false {
    # lower(resource.Type) == "aws::dynamodb::table"
    not input.Table.SSEDescription.Status
}

dynamodb_encrypt_err = "AWS DynamoDB encrypted using AWS owned CMK instead of AWS managed CMK" {
    not dynamodb_encrypt
}

dynamodb_encrypt_metadata := {
    "Policy Code": "PR-AWS-CLD-DD-001",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS DynamoDB encrypted using AWS owned CMK instead of AWS managed CMK",
    "Policy Description": "This policy identifies the DynamoDB tables that use AWS owned CMK (default ) instead of AWS managed CMK (KMS ) to encrypt data. AWS managed CMK provide additional features such as the ability to view the CMK and key policy, and audit the encryption and decryption of DynamoDB tables.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dynamodb-table.html"
}


#
# PR-AWS-CLD-DD-002
#

default dynamodb_PITR_enable = true

dynamodb_PITR_enable = false {
    # lower(resource.Type) == "aws::dynamodb::table"
    not input.ContinuousBackupsDescription.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus
}

dynamodb_PITR_enable = false {
    # lower(resource.Type) == "aws::dynamodb::table"
    lower(input.ContinuousBackupsDescription.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus) != "enabled"
}

dynamodb_PITR_enable_err = "Ensure DynamoDB PITR is enabled" {
    not dynamodb_PITR_enable
}

dynamodb_PITR_enable_metadata := {
    "Policy Code": "PR-AWS-CLD-DD-002",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure DynamoDB PITR is enabled",
    "Policy Description": "DynamoDB Point-In-Time Recovery (PITR) is an automatic backup service for DynamoDB table data that helps protect your DynamoDB tables from accidental write or delete operations. Once enabled, PITR provides continuous backups that can be controlled using various programmatic parameters. PITR can also be used to restore table data from any point in time during the last 35 days, as well as any incremental backups of DynamoDB tables",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dynamodb-table.html"
}


#
# PR-AWS-CLD-DD-003
#

default dynamodb_kinesis_stream = true

dynamodb_kinesis_stream = false {
    # lower(resource.Type) == "aws::dynamodb::table"
    KinesisDataStreamDestinations := input.KinesisDataStreamDestinations[_]
    count(KinesisDataStreamDestinations.StreamArn) == 0
}

dynamodb_kinesis_stream = false {
    # lower(resource.Type) == "aws::dynamodb::table"
    KinesisDataStreamDestinations := input.KinesisDataStreamDestinations[_]
    not KinesisDataStreamDestinations.StreamArn
}

dynamodb_kinesis_stream_err = "Dynamo DB kinesis specification property should not be null" {
    not dynamodb_kinesis_stream
}

dynamodb_kinesis_stream_metadata := {
    "Policy Code": "PR-AWS-CLD-DD-003",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Dynamo DB kinesis specification property should not be null",
    "Policy Description": "Dynamo DB kinesis specification property should not be null",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dynamodb-kinesisstreamspecification.html#cfn-dynamodb-kinesisstreamspecification-streamarn"
}


#
# PR-AWS-CLD-DD-004
# aws::dynamodb::table
# AWS::KMS::Key

default dynamodb_not_customer_managed_key = true

dynamodb_not_customer_managed_key = false {
    X := input.TEST_DD[_]
    Y := input.TEST_KMS[_]
    X.Table.SSEDescription.Status == "ENABLED"
    X.Table.SSEDescription.SSEType == "KMS"
    has_property(X.Table.SSEDescription, "KMSMasterKeyArn")
	X.Table.SSEDescription.KMSMasterKeyArn == Y.KeyMetadata.Arn
	Y.KeyMetadata.KeyManager != "CUSTOMER"
}

dynamodb_not_customer_managed_key_err = "Ensure AWS DynamoDB does not uses customer managed CMK key to ensure encryption at rest." {
    not dynamodb_not_customer_managed_key
}

dynamodb_not_customer_managed_key_metadata := {
    "Policy Code": "PR-AWS-CLD-DD-004",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS DynamoDB does not uses customer managed CMK key to ensure encryption at rest.",
    "Policy Description": "It checks if the default AWS Key is used for encryption. GS mandates CMK to be used for encryption.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/dynamodb.html#DynamoDB.Client.describe_table"
}


#
# PR-AWS-CLD-EC-001
#

default cache_failover = true

cache_failover = false {
    # lower(resource.Type) == "aws::elasticache::replicationgroup"
    ReplicationGroups := input.ReplicationGroups[_]
    lower(ReplicationGroups.AutomaticFailover) != "enabled"
    lower(ReplicationGroups.AutomaticFailover) != "enabling"
}

cache_failover_err = "AWS ElastiCache Redis cluster with Multi-AZ Automatic Failover feature set to disabled" {
    not cache_failover
}

cache_failover_metadata := {
    "Policy Code": "PR-AWS-CLD-EC-001",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS ElastiCache Redis cluster with Multi-AZ Automatic Failover feature set to disabled",
    "Policy Description": "This policy identifies ElastiCache Redis clusters which have Multi-AZ Automatic Failover feature set to disabled. It is recommended to enable the Multi-AZ Automatic Failover feature for your Redis Cache cluster, which will improve primary node reachability by providing read replica in case of network connectivity loss or loss of availability in the primary's availability zone for read/write operations._x005F_x000D_ Note: Redis cluster Multi-AZ with automatic failover does not support T1 and T2 cache node types and is only available if the cluster has at least one read replica.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html"
}

#
# PR-AWS-CLD-EC-002
#

default cache_redis_auth = true

cache_redis_auth = false {
    # lower(resource.Type) == "aws::elasticache::replicationgroup"
    ReplicationGroups := input.ReplicationGroups[_]
    not ReplicationGroups.AuthTokenEnabled
}

cache_redis_auth_err = "AWS ElastiCache Redis cluster with encryption for data at rest disabled" {
    not cache_redis_auth
}

cache_redis_auth_metadata := {
    "Policy Code": "PR-AWS-CLD-EC-002",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS ElastiCache Redis cluster with Redis AUTH feature disabled",
    "Policy Description": "This policy identifies ElastiCache Redis clusters which have Redis AUTH feature disabled. Redis AUTH can improve data security by requiring the user to enter a password before they are granted permission to execute Redis commands on a password protected Redis server.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html"
}


#
# PR-AWS-CLD-EC-003
#

default cache_redis_encrypt = true


cache_redis_encrypt = false {
    # lower(resource.Type) == "aws::elasticache::replicationgroup"
    ReplicationGroups := input.ReplicationGroups[_]
    not ReplicationGroups.AtRestEncryptionEnabled
}

cache_redis_encrypt_err = "AWS ElastiCache Redis cluster with encryption for data at rest disabled" {
    not cache_redis_encrypt
}

cache_redis_encrypt_metadata := {
    "Policy Code": "PR-AWS-CLD-EC-003",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS ElastiCache Redis cluster with encryption for data at rest disabled",
    "Policy Description": "This policy identifies ElastiCache Redis clusters which have encryption for data at rest(at-rest) is disabled. It is highly recommended to implement at-rest encryption in order to prevent unauthorized users from reading sensitive data saved to persistent media available on your Redis clusters and their associated cache storage systems.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html"
}


#
# PR-AWS-CLD-EC-004
#

default cache_encrypt = true

cache_encrypt = false {
    # lower(resource.Type) == "aws::elasticache::replicationgroup"
    ReplicationGroups := input.ReplicationGroups[_]
    not ReplicationGroups.TransitEncryptionEnabled
}

cache_encrypt_err = "AWS ElastiCache Redis cluster with in-transit encryption disabled" {
    not cache_encrypt
}

cache_encrypt_metadata := {
    "Policy Code": "PR-AWS-CLD-EC-004",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS ElastiCache Redis cluster with in-transit encryption disabled",
    "Policy Description": "This policy identifies ElastiCache Redis clusters which have in-transit encryption disabled. It is highly recommended to implement in-transit encryption in order to protect data from unauthorized access as it travels through the network, between clients and cache servers. Enabling data encryption in-transit helps prevent unauthorized users from reading sensitive data between your Redis clusters and their associated cache storage systems.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html"
}


#
# PR-AWS-CLD-EC-005
#

default cache_ksm_key = true

cache_ksm_key = false {
    # lower(resource.Type) == "aws::elasticache::replicationgroup"
    ReplicationGroups := input.ReplicationGroups[_]
    not ReplicationGroups.KmsKeyId
}

cache_ksm_key = false {
    # lower(resource.Type) == "aws::elasticache::replicationgroup"
    ReplicationGroups := input.ReplicationGroups[_]
    not startswith(ReplicationGroups.KmsKeyId, "arn:")
}

cache_ksm_key_err = "Ensure that ElastiCache replication Group (Redis) are encrypted at rest with customer managed CMK key" {
    not cache_ksm_key
}

cache_ksm_key_metadata := {
    "Policy Code": "PR-AWS-CLD-EC-005",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure that ElastiCache replication Group (Redis) are encrypted at rest with customer managed CMK key",
    "Policy Description": "This policy identifies ElastiCache Redis clusters which have in-transit encryption disabled. It is highly recommended to implement in-transit encryption in order to protect data from unauthorized access as it travels through the network, between clients and cache servers. Enabling data encryption in-transit helps prevent unauthorized users from reading sensitive data between your Redis clusters and their associated cache storage systems.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-kmskeyid"
}

#
# PR-AWS-CLD-EC-009
#

default cache_replication_group_id = true

cache_replication_group_id = false {
    # lower(resource.Type) == "aws::elasticache::replicationgroup"
    ReplicationGroups := input.ReplicationGroups[_]
    not ReplicationGroups.ReplicationGroupId
}

cache_replication_group_id = false {
    # lower(resource.Type) == "aws::elasticache::replicationgroup"
    ReplicationGroups := input.ReplicationGroups[_]
    ReplicationGroups.ReplicationGroupId == ""
}

cache_replication_group_id = false {
    # lower(resource.Type) == "aws::elasticache::replicationgroup"
    ReplicationGroups := input.ReplicationGroups[_]
    ReplicationGroups.ReplicationGroupId == null
}

cache_replication_group_id = false {
    # lower(resource.Type) == "aws::elasticache::replicationgroup"
    ReplicationGroups := input.ReplicationGroups[_]
    contains(lower(ReplicationGroups.ReplicationGroupId), "*")
}

cache_replication_group_id_err = "Ensure ElastiCache (Redis) replicationGroupId is not empty or contains wildcards (*)." {
    not cache_replication_group_id
}

cache_replication_group_id_metadata := {
    "Policy Code": "PR-AWS-CLD-EC-009",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure ElastiCache (Redis) replicationGroupId is not empty or contains wildcards (*).",
    "Policy Description": "This checks if the replication group ID for Redis is set to empty or a * to allow all.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/elasticache.html#ElastiCache.Client.describe_replication_groups"
}

#
# PR-AWS-CLD-EC-007
#

default automatic_backups_for_redis_cluster = true

automatic_backups_for_redis_cluster = false {
    # lower(resource.Type) == "aws::elasticache::cachecluster"
    CacheCluster := input.CacheClusters[_]
    CacheCluster.SnapshotRetentionLimit == 0
}

automatic_backups_for_redis_cluster_err = "Ensure in AWS ElastiCache, automatic backups is enabled for Redis cluster." {
    not automatic_backups_for_redis_cluster
}

automatic_backups_for_redis_cluster_metadata := {
    "Policy Code": "PR-AWS-CLD-EC-007",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure in AWS ElastiCache, automatic backups is enabled for Redis cluster.",
    "Policy Description": "It checks if automatic backups are enabled for the Redis cluster.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/elasticache.html#ElastiCache.Client.describe_cache_clusters"
}

#
# PR-AWS-CLD-EC-008
#

default redis_with_intransit_encryption = true

redis_with_intransit_encryption = false {
    # lower(resource.Type) == "aws::elasticache::cachecluster"
    CacheCluster := input.CacheClusters[_]
    CacheCluster.TransitEncryptionEnabled == available_false_choices[_]
    not CacheCluster.ReplicationGroupId
}

redis_with_intransit_encryption_err = "Ensure ElastiCache Redis with in-transit encryption is disabled (Non-replication group)." {
    not redis_with_intransit_encryption
}

redis_with_intransit_encryption_metadata := {
    "Policy Code": "PR-AWS-CLD-EC-008",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure ElastiCache Redis with in-transit encryption is disabled (Non-replication group).",
    "Policy Description": "It identifies ElastiCache Redis that are in non-replication groups or individual ElastiCache Redis and have in-transit encryption disabled. It is highly recommended to implement in-transit encryption in order to protect data from unauthorized access as it travels through the network, between clients and cache servers. Enabling data encryption in-transit helps prevent unauthorized users from reading sensitive data between your Redis and their associated cache storage systems.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/elasticache.html#ElastiCache.Client.describe_cache_clusters"
}


#
# PR-AWS-CLD-EC-010
# aws::elasticache::cachecluster
# aws::elasticache::replicationgroup

default cache_cluster_vpc = true

cache_cluster_vpc = false {
    X := input.TEST_EC_01[_]
    CacheCluster := X.CacheClusters[_]
    Y := input.TEST_EC[_]
    ReplicationGroup := Y.ReplicationGroups[_]
    MemberCluster := ReplicationGroup.MemberClusters[_]
    contains(MemberCluster, CacheCluster.CacheClusterId)
    CacheCluster.CacheClusterStatus == "available"
    not CacheCluster.CacheSubnetGroupName
}

cache_cluster_vpc = false {
    X := input.TEST_EC_01[_]
    CacheCluster := X.CacheClusters[_]
    Y := input.TEST_EC[_]
    ReplicationGroup := Y.ReplicationGroups[_]
    MemberCluster := ReplicationGroup.MemberClusters[_]
    contains(MemberCluster, CacheCluster.CacheClusterId)
    CacheCluster.CacheClusterStatus == "available"
    CacheCluster.CacheSubnetGroupName == ""
}

cache_cluster_vpc = false {
    X := input.TEST_EC_01[_]
    CacheCluster := X.CacheClusters[_]
    Y := input.TEST_EC[_]
    ReplicationGroup := Y.ReplicationGroups[_]
    MemberCluster := ReplicationGroup.MemberClusters[_]
    contains(MemberCluster, CacheCluster.CacheClusterId)
    CacheCluster.CacheClusterStatus == "available"
    CacheCluster.CacheSubnetGroupName == null
}

cache_cluster_vpc_err = "Ensure AWS ElastiCache cluster is associated with VPC." {
    not cache_cluster_vpc
}

cache_cluster_vpc_metadata := {
    "Policy Code": "PR-AWS-CLD-EC-010",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS ElastiCache cluster is associated with VPC.",
    "Policy Description": "It identifies ElastiCache Clusters which are not associated with VPC. It is highly recommended to associate ElastiCache with VPC, as provides virtual network in your own logically isolated area and features such as selecting IP address range, creating subnets, and configuring route tables, network gateways, and security settings. NOTE: If you created your AWS account before 2013-12-04, you might have support for the EC2-Classic platform in some regions. AWS has deprecated the use of Amazon EC2-Classic for launching ElastiCache clusters. All current generation nodes are launched in Amazon Virtual Private Cloud only. So this policy only applies legacy ElastiCache clusters which are created using EC2-Classic.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/elasticache.html#ElastiCache.Client.describe_cache_clusters"
}


#
# PR-AWS-CLD-DMS-001
#

default dms_endpoint = true

dms_endpoint = false {
    # lower(resource.Type) == "aws::dms::endpoint"
    Endpoints := input.Endpoints[_]
    lower(Endpoints.EngineName) != "s3"
    lower(Endpoints.SslMode) == "none"
}

dms_endpoint = false {
    # lower(resource.Type) == "aws::dms::endpoint"
    Endpoints := input.Endpoints[_]
    lower(Endpoints.EngineName) != "s3"
    not Endpoints.SslMode
}

dms_endpoint_err = "Ensure DMS endpoints are supporting SSL configuration" {
    not dms_endpoint
}

dms_endpoint_metadata := {
    "Policy Code": "PR-AWS-CLD-DMS-001",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure DMS endpoints are supporting SSL configuration",
    "Policy Description": "This policy identifies Database Migration Service (DMS) endpoints that are not configured with SSL to encrypt connections for source and target endpoints. It is recommended to use SSL connection for source and target endpoints; enforcing SSL connections help protect against 'man in the middle' attacks by encrypting the data stream between endpoint connections.\n\nNOTE: Not all databases use SSL in the same way. An Amazon Redshift endpoint already uses an SSL connection and does not require an SSL connection set up by AWS DMS. So there are some exlcusions included in policy RQL to report only those endpoints which can be configured using DMS SSL feature. \n\nFor more details:\nhttps://docs.aws.amazon.com/dms/latest/userguide/CHAP_Security.html#CHAP_Security.SSL",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.amazonaws.cn/en_us/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-enginename"
}


#
# PR-AWS-CLD-DMS-002
#

default dms_public_access = true

dms_public_access = false {
    # lower(resource.Type) == "aws::dms::replicationinstance"
    replication_instances := input.ReplicationInstances[_]
    replication_instances.PubliclyAccessible == true
}

dms_public_access_err = "Ensure DMS replication instance is not publicly accessible" {
    not dms_public_access
}

dms_public_access_metadata := {
    "Policy Code": "PR-AWS-CLD-DMS-002",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure DMS replication instance is not publicly accessible",
    "Policy Description": "Ensure DMS replication instance is not publicly accessible, this might cause sensitive data leak.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationinstance.html#cfn-dms-replicationinstance-publiclyaccessible"
}


#
# PR-AWS-CLD-DMS-003
#

default dms_certificate_expiry = true

dms_certificate_expiry = false {
    # lower(resource.Type) == "aws::dms::replicationinstance"
    Certificate := input.Certificates[_]
    current_date_timestamp := time.now_ns()
	expiry_timestamp := round(Certificate.ValidToDate)
    expiry_timestamp_nanosecond := expiry_timestamp * 1000000000
    expiry_timestamp_nanosecond < current_date_timestamp
}

dms_certificate_expiry_err = "Ensure Database Migration Service (DMS) has not expired certificates" {
    not dms_certificate_expiry
}

dms_certificate_expiry_metadata := {
    "Policy Code": "PR-AWS-CLD-DMS-003",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure Database Migration Service (DMS) has not expired certificates",
    "Policy Description": "This policy identifies expired certificates that are in AWS Database Migration Service (DMS). AWS Database Migration Service (DMS) Certificate service is the preferred tool to provision, manage, and deploy your DMS endpoint certificates. As a best practice, it is recommended to delete expired certificates.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/cli/latest/reference/dms/describe-certificates.html"
}


#
# PR-AWS-CLD-DMS-004
# aws::dms::replicationinstance

default dms_gs_managed_key = true

dms_gs_managed_key = false {
    X := input.TEST_DMS_02[_]
    ReplicationInstance := X.ReplicationInstances[_]
    Y := input.TEST_KMS[_]
	ReplicationInstance.KmsKeyId == Y.KeyMetadata.KeyId
    Y.KeyMetadata.KeyManager != "CUSTOMER"
}

dms_gs_managed_key = false {
    X := input.TEST_DMS_02[_]
    ReplicationInstance := X.ReplicationInstances[_]
    Y := input.TEST_KMS[_]
	ReplicationInstance.KmsKeyId == Y.KeyMetadata.Arn
    Y.KeyMetadata.KeyManager != "CUSTOMER"
}

dms_gs_managed_key_err = "Ensure DMS replication instance in encrypted by GS provided CMK." {
    not dms_gs_managed_key
}

dms_gs_managed_key_metadata := {
    "Policy Code": "PR-AWS-CLD-DMS-004",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure DMS replication instance in encrypted by GS provided CMK.",
    "Policy Description": "It checks if the default AWS Key is used for encryption. GS mandates CMK to be used for encryption.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/dms.html#DatabaseMigrationService.Client.describe_replication_instances"
}
