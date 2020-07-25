package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html
# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-rds-database-instance.html

#
# Id: 119
#

default rds_cluster_encrypt = null

aws_issue["rds_cluster_encrypt"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::rds::dbcluster"
    not resource.Properties.StorageEncrypted
}

rds_cluster_encrypt {
    lower(input.resources[_].Type) == "aws::rds::dbcluster"
    not aws_issue["rds_cluster_encrypt"]
}

rds_cluster_encrypt = false {
    aws_issue["rds_cluster_encrypt"]
}

rds_cluster_encrypt_err = "AWS RDS DB cluster encryption is disabled" {
    aws_issue["rds_cluster_encrypt"]
}

#
# Id: 121
#

default rds_public = null

aws_issue["rds_public"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::rds::dbinstance"
    resource.Properties.PubliclyAccessible
}

rds_public {
    lower(input.resources[_].Type) == "aws::rds::dbinstance"
    not aws_issue["rds_public"]
}

rds_public = false {
    aws_issue["rds_public"]
}

rds_public_err = "AWS RDS DB cluster encryption is disabled" {
    aws_issue["rds_public"]
}

#
# Id: 125
#

default rds_encrypt = null

aws_issue["rds_encrypt"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::rds::dbinstance"
    not resource.Properties.StorageEncrypted
}

rds_encrypt {
    lower(input.resources[_].Type) == "aws::rds::dbinstance"
    not aws_issue["rds_encrypt"]
}

rds_encrypt = false {
    aws_issue["rds_encrypt"]
}

rds_encrypt_err = "AWS RDS instance is not encrypted" {
    aws_issue["rds_encrypt"]
}

#
# Id: 127
#

default rds_multiaz = null

aws_attribute_absence["rds_multiaz"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::rds::dbinstance"
    not resource.Properties.Engine
}

aws_issue["rds_multiaz"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::rds::dbinstance"
    lower(resource.Properties.Engine) != "aurora"
    lower(resource.Properties.Engine) != "sqlserver"
    not resource.Properties.MultiAZ
}

rds_multiaz {
    lower(input.resources[_].Type) == "aws::rds::dbinstance"
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

rds_multiaz_miss_err = "RDS dbcluster attribute Engine missing in the resource" {
    aws_attribute_absence["rds_multiaz"]
}

#
# Id: 128
#

default rds_snapshot = null

aws_issue["rds_snapshot"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::rds::dbinstance"
    not resource.Properties.CopyTagsToSnapshot
}

rds_snapshot {
    lower(input.resources[_].Type) == "aws::rds::dbinstance"
    not aws_issue["rds_snapshot"]
}

rds_snapshot = false {
    aws_issue["rds_snapshot"]
}

rds_snapshot_err = "AWS RDS instance with copy tags to snapshots disabled" {
    aws_issue["rds_snapshot"]
}

#
# Id: 129
#

default rds_backup = null

aws_attribute_absence["rds_backup"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::rds::dbinstance"
    not resource.Properties.BackupRetentionPeriod
}

aws_issue["rds_backup"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::rds::dbinstance"
    to_number(resource.Properties.BackupRetentionPeriod) == 0
}

rds_backup {
    lower(input.resources[_].Type) == "aws::rds::dbinstance"
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

#
# Id: 130
#

default rds_upgrade = null

aws_issue["rds_upgrade"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::rds::dbinstance"
    not resource.Properties.AutoMinorVersionUpgrade
}

rds_upgrade {
    lower(input.resources[_].Type) == "aws::rds::dbinstance"
    not aws_issue["rds_upgrade"]
}

rds_upgrade = false {
    aws_issue["rds_upgrade"]
}

rds_upgrade_err = "AWS RDS minor upgrades not enabled" {
    aws_issue["rds_upgrade"]
}

#
# Id: 131
#

default rds_retention = null

aws_attribute_absence["rds_retention"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::rds::dbinstance"
    not resource.Properties.BackupRetentionPeriod
}

aws_issue["rds_retention"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::rds::dbinstance"
    to_number(resource.Properties.BackupRetentionPeriod) < 7
}

rds_retention {
    lower(input.resources[_].Type) == "aws::rds::dbinstance"
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
