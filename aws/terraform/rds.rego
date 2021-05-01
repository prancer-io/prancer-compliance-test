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
    not resource.properties.storage_encrypted
}

rds_cluster_encrypt {
    lower(input.resources[_].type) == "aws_rds_cluster"
    not aws_issue["rds_cluster_encrypt"]
}

rds_cluster_encrypt = false {
    aws_issue["rds_cluster_encrypt"]
}

rds_cluster_encrypt_err = "AWS RDS DB cluster encryption is disabled" {
    aws_issue["rds_cluster_encrypt"]
}

#
# PR-AWS-0121-TRF
#

default rds_public = null

aws_issue["rds_public"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_db_instance"
    resource.properties.publicly_accessible
}

rds_public {
    lower(input.resources[_].type) == "aws_db_instance"
    not aws_issue["rds_public"]
}

rds_public = false {
    aws_issue["rds_public"]
}

rds_public_err = "AWS RDS database instance is publicly accessible" {
    aws_issue["rds_public"]
}

#
# PR-AWS-0125-TRF
#

default rds_encrypt = null

aws_issue["rds_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_db_instance"
    not resource.properties.storage_encrypted
}

rds_encrypt {
    lower(input.resources[_].type) == "aws_db_instance"
    not aws_issue["rds_encrypt"]
}

rds_encrypt = false {
    aws_issue["rds_encrypt"]
}

rds_encrypt_err = "AWS RDS instance is not encrypted" {
    aws_issue["rds_encrypt"]
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
    not resource.properties.multi_az
}

rds_multiaz {
    lower(input.resources[_].type) == "aws_db_instance"
    not aws_issue["rds_multiaz"]
    not aws_attribute_absence["rds_multiaz"]
}

rds_multiaz = false {
    aws_issue["rds_multiaz"]
}

rds_multiaz = false {
    aws_attribute_absence["rds_multiaz"]
}

rds_multiaz_err = "AWS RDS instance with Multi-Availability Zone disabled" {
    aws_issue["rds_multiaz"]
}

rds_multiaz_miss_err = "RDS dbcluster attribute engine missing in the resource" {
    aws_attribute_absence["rds_multiaz"]
}

#
# PR-AWS-0128-TRF
#

default rds_snapshot = null

aws_issue["rds_snapshot"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_db_instance"
    not resource.properties.copy_tags_to_snapshot
}

rds_snapshot {
    lower(input.resources[_].type) == "aws_db_instance"
    not aws_issue["rds_snapshot"]
}

rds_snapshot = false {
    aws_issue["rds_snapshot"]
}

rds_snapshot_err = "AWS RDS instance with copy tags to snapshots disabled" {
    aws_issue["rds_snapshot"]
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
}

rds_backup_miss_err = "RDS attribute backup_retention_period missing in the resource" {
    aws_attribute_absence["rds_backup"]
}

#
# PR-AWS-0130-TRF
#

default rds_upgrade = null

aws_issue["rds_upgrade"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_db_instance"
    not resource.properties.auto_minor_version_upgrade
}

rds_upgrade {
    lower(input.resources[_].type) == "aws_db_instance"
    not aws_issue["rds_upgrade"]
}

rds_upgrade = false {
    aws_issue["rds_upgrade"]
}

rds_upgrade_err = "AWS RDS minor upgrades not enabled" {
    aws_issue["rds_upgrade"]
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
}

rds_retention_miss_err = "RDS attribute backup_retention_period missing in the resource" {
    aws_attribute_absence["rds_retention"]
}
