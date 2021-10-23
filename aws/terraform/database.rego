package rule


#
# PR-AWS-TRF-DD-001
#

default dynamodb_encrypt = null

aws_attribute_absence["dynamodb_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_dynamodb_table"
    not resource.properties.server_side_encryption
}

aws_issue["dynamodb_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_dynamodb_table"
    count([c | resource.properties.server_side_encryption[_]; c:=1]) == 0
}

aws_issue["dynamodb_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_dynamodb_table"
    server_side_encryption := resource.properties.server_side_encryption[_]
    lower(server_side_encryption.enabled) == "false"
}

aws_bool_issue["dynamodb_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_dynamodb_table"
    server_side_encryption := resource.properties.server_side_encryption[_]
    not server_side_encryption.enabled
}

dynamodb_encrypt {
    lower(input.resources[_].type) == "aws_dynamodb_table"
    not aws_issue["dynamodb_encrypt"]
    not aws_bool_issue["dynamodb_encrypt"]
    not aws_attribute_absence["dynamodb_encrypt"]
}

dynamodb_encrypt = false {
    aws_issue["dynamodb_encrypt"]
}

dynamodb_encrypt = false {
    aws_bool_issue["dynamodb_encrypt"]
}

dynamodb_encrypt = false {
    aws_attribute_absence["dynamodb_encrypt"]
}

dynamodb_encrypt_err = "AWS DynamoDB encrypted using AWS owned CMK instead of AWS managed CMK" {
    aws_issue["dynamodb_encrypt"]
} else = "AWS DynamoDB encrypted using AWS owned CMK instead of AWS managed CMK" {
    aws_bool_issue["dynamodb_encrypt"]
} else = "DynamoDB attribute server_side_encryption missing in the resource" {
    aws_attribute_absence["dynamodb_encrypt"]
}

dynamodb_encrypt_metadata := {
    "Policy Code": "PR-AWS-TRF-DD-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS DynamoDB encrypted using AWS owned CMK instead of AWS managed CMK",
    "Policy Description": "This policy identifies the DynamoDB tables that use AWS owned CMK (default ) instead of AWS managed CMK (KMS ) to encrypt data. AWS managed CMK provide additional features such as the ability to view the CMK and key policy, and audit the encryption and decryption of DynamoDB tables.",
    "Resource Type": "aws_dynamodb_table",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dynamodb-table.html"
}

#
# PR-AWS-TRF-EC-001
#

default cache_failover = null

aws_issue["cache_failover"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elasticache_replication_group"
    lower(resource.properties.automatic_failover_enabled) == "false"
}

aws_bool_issue["cache_failover"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elasticache_replication_group"
    resource.properties.automatic_failover_enabled == false
}

cache_failover {
    lower(input.resources[i].type) == "aws_elasticache_replication_group"
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
    "Policy Code": "PR-AWS-TRF-EC-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS ElastiCache Redis cluster with Multi-AZ Automatic Failover feature set to disabled",
    "Policy Description": "This policy identifies ElastiCache Redis clusters which have Multi-AZ Automatic Failover feature set to disabled. It is recommended to enable the Multi-AZ Automatic Failover feature for your Redis Cache cluster, which will improve primary node reachability by providing read replica in case of network connectivity loss or loss of availability in the primary's availability zone for read/write operations._x005F_x000D_ Note: Redis cluster Multi-AZ with automatic failover does not support T1 and T2 cache node types and is only available if the cluster has at least one read replica.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html"
}

#
# PR-AWS-TRF-EC-002
#

default cache_redis_auth = null

aws_attribute_absence["cache_redis_auth"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elasticache_replication_group"
    not resource.properties.auth_token
}

aws_issue["cache_redis_auth"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elasticache_replication_group"
    count(resource.properties.auth_token) == 0
}

aws_issue["cache_redis_auth"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elasticache_replication_group"
    lower(resource.properties.transit_encryption_enabled) == "false"
}

aws_bool_issue["cache_redis_auth"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elasticache_replication_group"
    not resource.properties.transit_encryption_enabled
}

cache_redis_auth {
    lower(input.resources[i].type) == "aws_elasticache_replication_group"
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

cache_redis_auth_miss_err = "ElastiCache Redis cluster attribute auth_token missing in the resource" {
    aws_attribute_absence["cache_redis_auth"]
}

cache_redis_auth_metadata := {
    "Policy Code": "PR-AWS-TRF-EC-002",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS ElastiCache Redis cluster with Redis AUTH feature disabled",
    "Policy Description": "This policy identifies ElastiCache Redis clusters which have Redis AUTH feature disabled. Redis AUTH can improve data security by requiring the user to enter a password before they are granted permission to execute Redis commands on a password protected Redis server.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html"
}

#
# PR-AWS-TRF-EC-003
#

default cache_redis_encrypt = null

aws_issue["cache_redis_encrypt"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elasticache_replication_group"
    lower(resource.properties.at_rest_encryption_enabled) == "false"
}

aws_bool_issue["cache_redis_encrypt"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elasticache_replication_group"
    not resource.properties.at_rest_encryption_enabled
}

cache_redis_encrypt {
    lower(input.resources[i].type) == "aws_elasticache_replication_group"
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
    "Policy Code": "PR-AWS-TRF-EC-003",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS ElastiCache Redis cluster with encryption for data at rest disabled",
    "Policy Description": "This policy identifies ElastiCache Redis clusters which have encryption for data at rest(at-rest) is disabled. It is highly recommended to implement at-rest encryption in order to prevent unauthorized users from reading sensitive data saved to persistent media available on your Redis clusters and their associated cache storage systems.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html"
}

#
# PR-AWS-TRF-EC-004
#

default cache_encrypt = null

aws_issue["cache_encrypt"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elasticache_replication_group"
    lower(resource.properties.transit_encryption_enabled) == "false"
}

aws_bool_issue["cache_encrypt"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elasticache_replication_group"
    not resource.properties.transit_encryption_enabled
}

cache_encrypt {
    lower(input.resources[i].type) == "aws_elasticache_replication_group"
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
    "Policy Code": "PR-AWS-TRF-EC-004",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS ElastiCache Redis cluster with in-transit encryption disabled",
    "Policy Description": "This policy identifies ElastiCache Redis clusters which have in-transit encryption disabled. It is highly recommended to implement in-transit encryption in order to protect data from unauthorized access as it travels through the network, between clients and cache servers. Enabling data encryption in-transit helps prevent unauthorized users from reading sensitive data between your Redis clusters and their associated cache storage systems.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html"
}

#
# PR-AWS-TRF-RDS-001
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
    "Policy Code": "PR-AWS-TRF-RDS-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS RDS DB cluster encryption is disabled",
    "Policy Description": "This policy identifies RDS DB clusters for which encryption is disabled. Amazon Aurora encrypted DB clusters provide an additional layer of data protection by securing your data from unauthorized access to the underlying storage. You can use Amazon Aurora encryption to increase data protection of your applications deployed in the cloud, and to fulfill compliance requirements for data-at-rest encryption._x005F_x000D_ NOTE: This policy is applicable only for Aurora DB clusters._x005F_x000D_ https://docs.aws.amazon.com/cli/latest/reference/rds/describe-db-clusters.html",
    "Resource Type": "aws_db_instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html"
}

#
# PR-AWS-TRF-RDS-002
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
    "Policy Code": "PR-AWS-TRF-RDS-002",
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
# PR-AWS-TRF-RDS-006
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
    "Policy Code": "PR-AWS-TRF-RDS-006",
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
# PR-AWS-TRF-RDS-007
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
    "Policy Code": "PR-AWS-TRF-RDS-007",
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
# PR-AWS-TRF-RDS-008
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
    "Policy Code": "PR-AWS-TRF-RDS-008",
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
# PR-AWS-TRF-RDS-009
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
    "Policy Code": "PR-AWS-TRF-RDS-009",
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
# PR-AWS-TRF-RDS-010
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
    "Policy Code": "PR-AWS-TRF-RDS-010",
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
# PR-AWS-TRF-RDS-011
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
    "Policy Code": "PR-AWS-TRF-RDS-011",
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
# PR-AWS-TRF-RDS-003
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
    "Policy Code": "PR-AWS-TRF-RDS-003",
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
# PR-AWS-TRF-RDS-004
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
    "Policy Code": "PR-AWS-TRF-RDS-004",
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
# PR-AWS-TRF-RDS-005
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
    "Policy Code": "PR-AWS-TRF-RDS-005",
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
# PR-AWS-TRF-DMS-001
#

default dms_endpoint = null

aws_issue["dms_endpoint"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_dms_endpoint"
    lower(resource.properties.engine_name) != "s3"
    lower(resource.properties.ssl_mode) == "none"
}

aws_issue["dms_endpoint"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_dms_endpoint"
    lower(resource.properties.engine_name) != "s3"
    not resource.properties.ssl_mode
}

dms_endpoint {
    lower(input.resources[i].type) == "aws_dms_endpoint"
    not aws_issue["dms_endpoint"]
}

dms_endpoint = false {
    aws_issue["dms_endpoint"]
}

dms_endpoint_err = "Ensure DMS endpoints are supporting SSL configuration" {
    aws_issue["dms_endpoint"]
}

dms_endpoint_metadata := {
    "Policy Code": "PR-AWS-TRF-DMS-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure DMS endpoints are supporting SSL configuration",
    "Policy Description": "This policy identifies Database Migration Service (DMS) endpoints that are not configured with SSL to encrypt connections for source and target endpoints. It is recommended to use SSL connection for source and target endpoints; enforcing SSL connections help protect against 'man in the middle' attacks by encrypting the data stream between endpoint connections.\n\nNOTE: Not all databases use SSL in the same way. An Amazon Redshift endpoint already uses an SSL connection and does not require an SSL connection set up by AWS DMS. So there are some exlcusions included in policy RQL to report only those endpoints which can be configured using DMS SSL feature. \n\nFor more details:\nhttps://docs.aws.amazon.com/dms/latest/userguide/CHAP_Security.html#CHAP_Security.SSL",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.amazonaws.cn/en_us/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-enginename"
}

#
# PR-AWS-TRF-EC-005
#

default cache_ksm_key = null

aws_issue["cache_ksm_key"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elasticache_replication_group"
    not resource.properties.kms_key_id
}

aws_issue["cache_ksm_key"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elasticache_replication_group"
    not startswith(resource.properties.kms_key_id, "arn:")
}

cache_ksm_key {
    lower(input.resources[i].type) == "aws_elasticache_replication_group"
    not aws_issue["cache_ksm_key"]
}

cache_ksm_key = false {
    aws_issue["cache_ksm_key"]
}

cache_ksm_key_err = "Ensure that ElastiCache replication Group (Redis) are encrypted at rest with customer managed CMK key" {
    aws_issue["cache_ksm_key"]
}

cache_ksm_key_metadata := {
    "Policy Code": "PR-AWS-TRF-EC-005",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that ElastiCache replication Group (Redis) are encrypted at rest with customer managed CMK key",
    "Policy Description": "This policy identifies ElastiCache Redis clusters which have in-transit encryption disabled. It is highly recommended to implement in-transit encryption in order to protect data from unauthorized access as it travels through the network, between clients and cache servers. Enabling data encryption in-transit helps prevent unauthorized users from reading sensitive data between your Redis clusters and their associated cache storage systems.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-kmskeyid"
}

#
# PR-AWS-TRF-EC-006
#

default cache_default_sg = null

aws_issue["cache_default_sg"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elasticache_replication_group"
    not resource.properties.security_group_names
}

aws_issue["cache_default_sg"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elasticache_replication_group"
    count(resource.properties.security_group_names) == 0
}

aws_issue["cache_default_sg"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elasticache_replication_group"
    cache_sg := resource.properties.security_group_names[_]
    count([c | lower(cache_sg) == "default"; c:=1]) != 0
}

cache_default_sg {
    lower(input.resources[i].type) == "aws_elasticache_replication_group"
    not aws_issue["cache_default_sg"]
}

cache_default_sg = false {
    aws_issue["cache_default_sg"]
}

cache_default_sg_err = "Ensure 'default' value is not used on Security Group setting for Redis cache engines" {
    aws_issue["cache_default_sg"]
}

cache_default_sg_metadata := {
    "Policy Code": "PR-AWS-TRF-EC-006",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure 'default' value is not used on Security Group setting for Redis cache engines",
    "Policy Description": "Ensure 'default' value is not used on Security Group setting for Redis cache engines",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-cachesubnetgroupname"
}

#
# PR-AWS-TRF-RDS-012
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
    "Policy Code": "PR-AWS-TRF-RDS-012",
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
# PR-AWS-TRF-DAX-001
#

default dax_encrypt = null

aws_issue["dax_encrypt"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_dax_cluster"
    lower(resource.properties.server_side_encryption) != "true"
}

aws_bool_issue["dax_encrypt"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_dax_cluster"
    not resource.properties.server_side_encryption
}

dax_encrypt {
    lower(input.resources[i].type) == "aws_dax_cluster"
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
    "Policy Code": "PR-AWS-TRF-DAX-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure DAX is securely encrypted at rest",
    "Policy Description": "Amazon DynamoDB Accelerator (DAX) encryption at rest provides an additional layer of data protection, helping secure your data from unauthorized access to underlying storage. With encryption at rest the data persisted by DAX on disk is encrypted using 256-bit Advanced Encryption Standard (AES-256). DAX writes data to disk as part of propagating changes from the primary node to read replicas. DAX encryption at rest automatically integrates with AWS KMS for managing the single service default key used to encrypt clusters.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dax-cluster-ssespecification.html"
}

#
# PR-AWS-TRF-DD-002
#

default dynamodb_PITR_enable = null

aws_issue["dynamodb_PITR_enable"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_dynamodb_table"
    point_in_time_recovery := resource.properties.point_in_time_recovery[_]
    lower(point_in_time_recovery.enabled) != "true"
}

aws_bool_issue["dynamodb_PITR_enable"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_dynamodb_table"
    point_in_time_recovery := resource.properties.point_in_time_recovery[_]
    not point_in_time_recovery.enabled
}

dynamodb_PITR_enable {
    lower(input.resources[i].type) == "aws_dynamodb_table"
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
    "Policy Code": "PR-AWS-TRF-DD-002",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure DynamoDB PITR is enabled",
    "Policy Description": "DynamoDB Point-In-Time Recovery (PITR) is an automatic backup service for DynamoDB table data that helps protect your DynamoDB tables from accidental write or delete operations. Once enabled, PITR provides continuous backups that can be controlled using various programmatic parameters. PITR can also be used to restore table data from any point in time during the last 35 days, as well as any incremental backups of DynamoDB tables",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dynamodb-table.html"
}

#
# PR-AWS-TRF-QLDB-001
#

default qldb_permission_mode = null

aws_issue["qldb_permission_mode"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_qldb_ledger"
    lower(resource.properties.permissions_mode) != "standard"
}

aws_issue["qldb_permission_mode"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_qldb_ledger"
    not resource.properties.permissions_mode
}

qldb_permission_mode {
    lower(input.resources[i].type) == "aws_qldb_ledger"
    not aws_issue["qldb_permission_mode"]
}

qldb_permission_mode = false {
    aws_issue["qldb_permission_mode"]
}

qldb_permission_mode_err = "Ensure QLDB ledger permissions mode is set to STANDARD" {
    aws_issue["qldb_permission_mode"]
}

qldb_permission_mode_metadata := {
    "Policy Code": "PR-AWS-TRF-QLDB-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure QLDB ledger permissions mode is set to STANDARD",
    "Policy Description": "In Amazon Quantum Ledger Database define PermissionsMode value to STANDARD permissions mode that enables access control with finer granularity for ledgers, tables, and PartiQL commands",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-qldb-ledger.html#cfn-qldb-ledger-permissionsmode"
}

#
# PR-AWS-TRF-RDS-013
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
    "Policy Code": "PR-AWS-TRF-RDS-013",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure RDS clusters and instances have deletion protection enabled",
    "Policy Description": "This rule Checks if an Amazon Relational Database Service (Amazon RDS) cluster has deletion protection enabled",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html"
}