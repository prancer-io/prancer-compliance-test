package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-redshift-cluster.html
# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-redshift-clusterparametergroup.html

#
# Id: 133
#

default redshift_encrypt_key = null

aws_attribute_absence["redshift_encrypt_key"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_redshift_cluster"
    not resource.properties.kms_key_id
}

aws_issue["redshift_encrypt_key"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_redshift_cluster"
    not startswith(lower(resource.properties.kms_key_id), "arn:")
}

aws_issue["redshift_encrypt_key"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_redshift_cluster"
    not resource.properties.encrypted
}

redshift_encrypt_key {
    lower(input.json.resources[_].type) == "aws_redshift_cluster"
    not aws_issue["redshift_encrypt_key"]
    not aws_attribute_absence["redshift_encrypt_key"]
}

redshift_encrypt_key = false {
    aws_issue["redshift_encrypt_key"]
}

redshift_encrypt_key = false {
    aws_attribute_absence["redshift_encrypt_key"]
}

redshift_encrypt_key_err = "AWS Redshift Cluster not encrypted using Customer Managed Key" {
    aws_issue["redshift_encrypt_key"]
}

redshift_encrypt_key_miss_err = "Redshift attribute kms_key_id missing in the resource" {
    aws_attribute_absence["redshift_encrypt_key"]
}

#
# Id: 134
#

default redshift_public = null

aws_issue["redshift_public"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_redshift_cluster"
    resource.properties.publicly_accessible
}

redshift_public {
    lower(input.json.resources[_].type) == "aws_redshift_cluster"
    not aws_issue["redshift_public"]
}

redshift_public = false {
    aws_issue["redshift_public"]
}

redshift_public_err = "AWS Redshift clusters should not be publicly accessible" {
    aws_issue["redshift_public"]
}

#
# Id: 135
#

default redshift_audit = null

aws_attribute_absence["redshift_audit"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_redshift_cluster"
    not resource.properties.logging.bucket_name
}

aws_issue["redshift_audit"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_redshift_cluster"
    count(resource.properties.logging.bucket_name) == 0
}

redshift_audit {
    lower(input.json.resources[_].type) == "aws_redshift_cluster"
    not aws_issue["redshift_audit"]
    not aws_attribute_absence["redshift_audit"]
}

redshift_audit = false {
    aws_issue["redshift_audit"]
}

redshift_audit = false {
    aws_attribute_absence["redshift_audit"]
}

redshift_audit_err = "AWS Redshift database does not have audit logging enabled" {
    aws_issue["redshift_audit"]
}

redshift_audit_miss_err = "Redshift attribute logging.bucket_name missing in the resource" {
    aws_attribute_absence["redshift_audit"]
}


#
# Id: 136
#

default redshift_require_ssl = null

aws_attribute_absence["redshift_require_ssl"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_redshift_parameter_group"
    not resource.properties.parameters
}

aws_issue["redshift_require_ssl"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_redshift_parameter_group"
    count([c | lower(resource.properties.parameters[_].name) == "require_ssl"; c := 1]) == 0
}

aws_issue["redshift_require_ssl"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_redshift_parameter_group"
    params = resource.properties.parameters[_]
    lower(params.name) == "require_ssl"
    lower(params.value) == "false"
}

redshift_require_ssl {
    lower(input.json.resources[_].type) == "aws_redshift_parameter_group"
    not aws_issue["redshift_require_ssl"]
    not aws_attribute_absence["redshift_require_ssl"]
}

redshift_require_ssl = false {
    aws_issue["redshift_require_ssl"]
}

redshift_require_ssl = false {
    aws_attribute_absence["redshift_require_ssl"]
}

redshift_require_ssl_err = "AWS Redshift does not have require_ssl configured" {
    aws_issue["redshift_require_ssl"]
}

redshift_require_ssl_miss_err = "Redshift attribute properties missing in the resource" {
    aws_attribute_absence["redshift_require_ssl"]
}

#
# Id: 137
#

default redshift_encrypt = null

aws_issue["redshift_encrypt"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_redshift_cluster"
    not resource.properties.encrypted
}

redshift_encrypt {
    lower(input.json.resources[_].type) == "aws_redshift_cluster"
    not aws_issue["redshift_encrypt"]
}

redshift_encrypt = false {
    aws_issue["redshift_encrypt"]
}

redshift_encrypt_err = "AWS Redshift instances are not encrypted" {
    aws_issue["redshift_encrypt"]
}
