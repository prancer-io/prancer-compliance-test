package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-redshift-cluster.html
# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-redshift-clusterparametergroup.html

#
# Id: 133
#

default redshift_encrypt_key = null

redshift_encrypt_key {
    lower(input.Type) == "aws::redshift::cluster"
    input.Properties.Encrypted == true
    startswith(lower(input.Properties.KmsKeyId), "arn:")
}

redshift_encrypt_key = false {
    lower(input.Type) == "aws::redshift::cluster"
    input.Properties.Encrypted == true
    not startswith(lower(input.Properties.KmsKeyId), "arn:")
}

redshift_encrypt_key = false {
    lower(input.Type) == "aws::redshift::cluster"
    input.Properties.Encrypted == false
}

redshift_encrypt_key_err = "AWS Redshift Cluster not encrypted using Customer Managed Key" {
    redshift_encrypt_key == false
}

#
# Id: 134
#

default redshift_public = null

redshift_public {
    lower(input.Type) == "aws::redshift::cluster"
    input.Properties.PubliclyAccessible == false
}

redshift_public = false {
    lower(input.Type) == "aws::redshift::cluster"
    input.Properties.PubliclyAccessible == true
}

redshift_public_err = "AWS Redshift clusters should not be publicly accessible" {
    redshift_public == false
}

#
# Id: 135
#

default redshift_audit = null

redshift_audit {
    lower(input.Type) == "aws::redshift::cluster"
    count(input.Properties.LoggingProperties.BucketName) > 0
}

redshift_audit = false {
    lower(input.Type) == "aws::redshift::cluster"
    count(input.Properties.LoggingProperties.BucketName) == 0
}

redshift_audit = false {
    lower(input.Type) == "aws::redshift::cluster"
    not input.Properties.LoggingProperties
}

redshift_audit = false {
    lower(input.Type) == "aws::redshift::cluster"
    not input.Properties.LoggingProperties.BucketName
}

redshift_audit_err = "AWS Redshift database does not have audit logging enabled" {
    redshift_audit == false
}

#
# Id: 136
#

default redshift_require_ssl = null

redshift_require_ssl {
    lower(input.Type) == "aws::redshift::clusterparametergroup"
    params = input.Properties.Parameters[_]
    lower(params.ParameterName) == "require_ssl"
    lower(params.ParameterValue) == "true"
}

redshift_require_ssl = false {
    lower(input.Type) == "aws::redshift::clusterparametergroup"
    count([c | lower(input.Properties.Parameters[_].ParameterName) == "require_ssl"; c := 1]) == 0
}

redshift_require_ssl = false {
    lower(input.Type) == "aws::redshift::clusterparametergroup"
    params = input.Properties.Parameters[_]
    lower(params.ParameterName) == "require_ssl"
    lower(params.ParameterValue) == "false"
}

redshift_require_ssl_err = "AWS Redshift does not have require_ssl configured" {
    redshift_require_ssl == false
}

#
# Id: 137
#

default redshift_encrypt = null

redshift_encrypt {
    lower(input.Type) == "aws::redshift::cluster"
    input.Properties.Encrypted == true
}

redshift_encrypt = false {
    lower(input.Type) == "aws::redshift::cluster"
    not input.Properties.Encrypted
}

redshift_encrypt = false {
    lower(input.Type) == "aws::redshift::cluster"
    input.Properties.Encrypted == false
}

redshift_encrypt_err = "AWS Redshift instances are not encrypted" {
    redshift_encrypt == false
}
