package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html
# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-rds-database-instance.html

#
# Id: 119
#

default rds_cluster_encrypt = null

rds_cluster_encrypt {
    lower(input.Type) == "aws::rds::dbcluster"
    input.Properties.StorageEncrypted == true
}

rds_cluster_encrypt = false {
    lower(input.Type) == "aws::rds::dbcluster"
    input.Properties.StorageEncrypted == false
}

rds_cluster_encrypt_err = "AWS RDS DB cluster encryption is disabled" {
    rds_cluster_encrypt == false
}

#
# Id: 121
#

default rds_public = null

rds_public {
    lower(input.Type) == "aws::rds::dbinstance"
    input.Properties.PubliclyAccessible == false
}

rds_public = false {
    lower(input.Type) == "aws::rds::dbinstance"
    input.Properties.PubliclyAccessible == true
}

rds_public_err = "AWS RDS database instance is publicly accessible" {
    rds_public == false
}

#
# Id: 125
#

default rds_encrypt = null

rds_encrypt {
    lower(input.Type) == "aws::rds::dbinstance"
    input.Properties.StorageEncrypted == true
}

rds_encrypt = false {
    lower(input.Type) == "aws::rds::dbinstance"
    input.Properties.StorageEncrypted == false
}

rds_encrypt_err = "AWS RDS instance is not encrypted" {
    rds_encrypt == false
}

#
# Id: 127
#

default rds_multiaz = null

rds_multiaz {
    lower(input.Type) == "aws::rds::dbinstance"
    lower(input.Properties.Engine) != "aurora"
    lower(input.Properties.Engine) != "sqlserver"
    input.Properties.MultiAZ == true
}

rds_multiaz {
    lower(input.Type) == "aws::rds::dbinstance"
    lower(input.Properties.Engine) == "aurora"
}

rds_multiaz {
    lower(input.Type) == "aws::rds::dbinstance"
    lower(input.Properties.Engine) == "sqlserver"
}

rds_multiaz = false {
    lower(input.Type) == "aws::rds::dbinstance"
    lower(input.Properties.Engine) != "aurora"
    lower(input.Properties.Engine) != "sqlserver"
    input.Properties.MultiAZ == false
}

rds_multiaz = false {
    lower(input.Type) == "aws::rds::dbinstance"
    lower(input.Properties.Engine) == "aurora"
    lower(input.Properties.Engine) == "sqlserver"
    not input.Properties.MultiAZ
}

rds_multiaz_err = "AWS RDS instance with Multi-Availability Zone disabled" {
    rds_multiaz == false
}

#
# Id: 128
#

default rds_snapshot = null

rds_snapshot {
    lower(input.Type) == "aws::rds::dbinstance"
    input.Properties.CopyTagsToSnapshot == true
}

rds_snapshot = false {
    lower(input.Type) == "aws::rds::dbinstance"
    input.Properties.CopyTagsToSnapshot == false
}

rds_snapshot = false {
    lower(input.Type) == "aws::rds::dbinstance"
    not input.Properties.CopyTagsToSnapshot
}

rds_snapshot_err = "AWS RDS instance with copy tags to snapshots disabled" {
    rds_snapshot == false
}

#
# Id: 129
#

default rds_backup = null

rds_backup {
    lower(input.Type) == "aws::rds::dbinstance"
    to_number(input.Properties.BackupRetentionPeriod) > 0
}

rds_backup = false {
    lower(input.Type) == "aws::rds::dbinstance"
    to_number(input.Properties.BackupRetentionPeriod) == 0
}

rds_backup = false {
    lower(input.Type) == "aws::rds::dbinstance"
    not input.Properties.BackupRetentionPeriod
}

rds_backup_err = "AWS RDS instance without Automatic Backup setting" {
    rds_backup == false
}

#
# Id: 130
#

default rds_upgrade = null

rds_upgrade {
    lower(input.Type) == "aws::rds::dbinstance"
    input.Properties.AutoMinorVersionUpgrade == true
}

rds_upgrade = false {
    lower(input.Type) == "aws::rds::dbinstance"
    input.Properties.AutoMinorVersionUpgrade == false
}

rds_upgrade_err = "AWS RDS minor upgrades not enabled" {
    rds_upgrade == false
}

#
# Id: 131
#

default rds_retention = null

rds_retention {
    lower(input.Type) == "aws::rds::dbinstance"
    to_number(input.Properties.BackupRetentionPeriod) >= 7
}

rds_retention = false {
    lower(input.Type) == "aws::rds::dbinstance"
    to_number(input.Properties.BackupRetentionPeriod) < 7
}

rds_retention = false {
    lower(input.Type) == "aws::rds::dbinstance"
    not input.Properties.BackupRetentionPeriod
}

rds_retention_err = "AWS RDS retention policy less than 7 days" {
    rds_retention == false
}
