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
