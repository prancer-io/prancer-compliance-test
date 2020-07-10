package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-efs-filesystem.html

#
# Id: 60
#

default efs_kms = null

efs_kms {
    lower(input.Type) == "aws::efs::filesystem"
    input.Properties.Encrypted == true
    startswith(input.Properties.KmsKeyId, "arn:")
}

efs_kms = false {
    lower(input.Type) == "aws::efs::filesystem"
    input.Properties.Encrypted == false
}

efs_kms = false {
    lower(input.Type) == "aws::efs::filesystem"
    not startswith(input.Properties.KmsKeyId, "arn:")
}

efs_kms_err = "AWS Elastic File System (EFS) not encrypted using Customer Managed Key" {
    efs_kms == false
}

#
# Id: 61
#

default efs_encrypt = null

efs_encrypt {
    lower(input.Type) == "aws::efs::filesystem"
    input.Properties.Encrypted == true
}

efs_encrypt = false {
    lower(input.Type) == "aws::efs::filesystem"
    input.Properties.Encrypted == false
}

efs_encrypt_err = "AWS Elastic File System (EFS) with encryption for data at rest disabled" {
    efs_encrypt == false
}
