package rule

# https://github.com/aws-controllers-k8s/rds-controller

#
# PR-AWS-0121-ACK
#

default rds_public = null

aws_issue["rds_public"] {
    lower(input.kind) == "dbinstance"
    input.spec.publiclyAccessible
}

rds_public {
    lower(input.kind) == "dbinstance"
    not aws_issue["rds_public"]
}

rds_public = false {
    aws_issue["rds_public"]
}

rds_public_err = "AWS RDS DB cluster encryption is disabled" {
    aws_issue["rds_public"]
}

rds_public_metadata := {
    "Policy Code": "PR-AWS-0121-ACK",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "ACK",
    "Policy Title": "AWS RDS database instance is publicly accessible",
    "Policy Description": "This policy identifies RDS database instances which are publicly accessible.DB instances should not be publicly accessible to protect the integrety of data.Public accessibility of DB instances can be modified by turning on or off the Public accessibility parameter.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://github.com/aws-controllers-k8s/rds-controller"
}

#
# PR-AWS-0125-ACK
#

default rds_encrypt = null

aws_issue["rds_encrypt"] {
    lower(input.kind) == "dbinstance"
    not input.spec.storageEncrypted
}

rds_encrypt {
    lower(input.kind) == "dbinstance"
    not aws_issue["rds_encrypt"]
}

rds_encrypt = false {
    aws_issue["rds_encrypt"]
}

rds_encrypt_err = "AWS RDS instance is not encrypted" {
    aws_issue["rds_encrypt"]
}

rds_encrypt_metadata := {
    "Policy Code": "PR-AWS-0125-ACK",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "ACK",
    "Policy Title": "AWS RDS instance is not encrypted",
    "Policy Description": "This policy identifies AWS RDS instances which are not encrypted. Amazon Relational Database Service (Amazon RDS) is a web service that makes it easier to set up and manage databases. Amazon allows customers to turn on encryption for RDS which is recommended for compliance and security reasons.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://github.com/aws-controllers-k8s/rds-controller"
}

#
# PR-AWS-0127-ACK
#

default rds_multiaz = null

aws_issue["rds_multiaz"] {
    lower(input.kind) == "dbinstance"
    not input.spec.engine
}

aws_issue["rds_multiaz"] {
    lower(input.kind) == "dbinstance"
    lower(input.spec.engine) != "aurora"
    lower(input.spec.engine) != "sqlserver"
    not input.spec.multiAZ
}

rds_multiaz {
    lower(input.kind) == "dbinstance"
    not aws_issue["rds_multiaz"]
}

rds_multiaz = false {
    aws_issue["rds_multiaz"]
}

rds_multiaz_err = "AWS RDS instance with Multi-Availability Zone disabled" {
    aws_issue["rds_multiaz"]
}

rds_multiaz_metadata := {
    "Policy Code": "PR-AWS-0127-ACK",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "ACK",
    "Policy Title": "AWS RDS instance with Multi-Availability Zone disabled",
    "Policy Description": "This policy identifies RDS instances which have Multi-Availability Zone(Multi-AZ) disabled. When RDS DB instance is enabled with Multi-AZ, RDS automatically creates a primary DB Instance and synchronously replicates the data to a standby instance in a different availability zone. These Multi-AZ deployments will improve primary node reachability by providing read replica in case of network connectivity loss or loss of availability in the primaryâ€™s availability zone for read/write operations, so by making them the best fit for production database workloads.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://github.com/aws-controllers-k8s/rds-controller"
}

#
# PR-AWS-0128-ACK
#

default rds_snapshot = null

aws_issue["rds_snapshot"] {
    lower(input.kind) == "dbinstance"
    not input.spec.copyTagsToSnapshot
}

rds_snapshot {
    lower(input.kind) == "dbinstance"
    not aws_issue["rds_snapshot"]
}

rds_snapshot = false {
    aws_issue["rds_snapshot"]
}

rds_snapshot_err = "AWS RDS instance with copy tags to snapshots disabled" {
    aws_issue["rds_snapshot"]
}

rds_snapshot_metadata := {
    "Policy Code": "PR-AWS-0128-ACK",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "ACK",
    "Policy Title": "AWS RDS instance with copy tags to snapshots disabled",
    "Policy Description": "This policy identifies RDS instances which have copy tags to snapshots disabled. Copy tags to snapshots copies all the user-defined tags from the DB instance to snapshots. Copying tags allow you to add metadata and apply access policies to your Amazon RDS resources.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://github.com/aws-controllers-k8s/rds-controller"
}

#
# PR-AWS-0129-ACK
#

default rds_backup = null

aws_issue["rds_backup"] {
    lower(input.kind) == "dbinstance"
    not input.spec.backupRetentionPeriod
}

aws_issue["rds_backup"] {
    lower(input.kind) == "dbinstance"
    to_number(input.spec.backupRetentionPeriod) == 0
}

rds_backup {
    lower(input.kind) == "dbinstance"
    not aws_issue["rds_backup"]
}

rds_backup = false {
    aws_issue["rds_backup"]
}

rds_backup_err = "AWS RDS instance without Automatic Backup setting" {
    aws_issue["rds_backup"]
}

rds_backup_metadata := {
    "Policy Code": "PR-AWS-0129-ACK",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "ACK",
    "Policy Title": "AWS RDS instance without Automatic Backup setting",
    "Policy Description": "This policy identifies RDS instances which are not set with the Automatic Backup setting. If Automatic Backup is set, RDS creates a storage volume snapshot of your DB instance, backing up the entire DB instance and not just individual databases which provide for point-in-time recovery. The automatic backup will happen during the specified backup window time and keeps the backups for a limited period of time as defined in the retention period. It is recommended to set Automatic backups for your critical RDS servers that will help in the data restoration process.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://github.com/aws-controllers-k8s/rds-controller"
}

#
# PR-AWS-0130-ACK
#

default rds_upgrade = null

aws_issue["rds_upgrade"] {
    lower(input.kind) == "dbinstance"
    input.spec.autoMinorVersionUpgrade == false
}

rds_upgrade {
    lower(input.kind) == "dbinstance"
    not aws_issue["rds_upgrade"]
}

rds_upgrade = false {
    aws_issue["rds_upgrade"]
}

rds_upgrade_err = "AWS RDS minor upgrades not enabled" {
    aws_issue["rds_upgrade"]
}

rds_upgrade_metadata := {
    "Policy Code": "PR-AWS-0130-ACK",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "ACK",
    "Policy Title": "AWS RDS minor upgrades not enabled",
    "Policy Description": "When Amazon Relational Database Service (Amazon RDS) supports a new version of a database engine, you can upgrade your DB instances to the new version. There are two kinds of upgrades: major version upgrades and minor version upgrades. Minor upgrades helps maintain a secure and stable RDS with minimal impact on the application. For this reason, we recommend that your automatic minor upgrade is enabled. Minor version upgrades only occur automatically if a minor upgrade replaces an unsafe version, such as a minor upgrade that contains bug fixes for a previous version.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://github.com/aws-controllers-k8s/rds-controller"
}

#
# PR-AWS-0131-ACK
#

default rds_retention = null

aws_issue["rds_retention"] {
    lower(input.kind) == "dbinstance"
    not input.spec.backupRetentionPeriod
}

aws_issue["rds_retention"] {
    lower(input.kind) == "dbinstance"
    to_number(input.spec.backupRetentionPeriod) < 7
}

rds_retention {
    lower(input.kind) == "dbinstance"
    not aws_issue["rds_retention"]
}

rds_retention = false {
    aws_issue["rds_retention"]
}

rds_retention_err = "AWS RDS retention policy less than 7 days" {
    aws_issue["rds_retention"]
}

rds_retention_metadata := {
    "Policy Code": "PR-AWS-0131-ACK",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "ACK",
    "Policy Title": "AWS RDS retention policy less than 7 days",
    "Policy Description": "RDS Retention Policies for Backups are an important part of your DR/BCP strategy. Recovering data from catastrophic failures, malicious attacks, or corruption often requires a several day window of potentially good backup material to leverage. As such, the best practice is to ensure your RDS clusters are retaining at least 7 days of backups, if not more (up to a maximum of 35).",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://github.com/aws-controllers-k8s/rds-controller"
}
