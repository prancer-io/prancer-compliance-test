package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-redshift-cluster.html
# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-redshift-clusterparametergroup.html

#
# PR-AWS-0133-CFR
#

default redshift_encrypt_key = null

aws_attribute_absence["redshift_encrypt_key"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::redshift::cluster"
    not resource.Properties.KmsKeyId
}

aws_issue["redshift_encrypt_key"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::redshift::cluster"
    not startswith(lower(resource.Properties.KmsKeyId), "arn:")
}

aws_issue["redshift_encrypt_key"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::redshift::cluster"
    lower(resource.Properties.Encrypted) == "true"
}

aws_bool_issue["redshift_encrypt_key"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::redshift::cluster"
    not resource.Properties.Encrypted
}

redshift_encrypt_key {
    lower(input.Resources[i].Type) == "aws::redshift::cluster"
    not aws_issue["redshift_encrypt_key"]
    not aws_bool_issue["redshift_encrypt_key"]
    not aws_attribute_absence["redshift_encrypt_key"]
}

redshift_encrypt_key = false {
    aws_issue["redshift_encrypt_key"]
}

redshift_encrypt_key = false {
    aws_bool_issue["redshift_encrypt_key"]
}

redshift_encrypt_key = false {
    aws_attribute_absence["redshift_encrypt_key"]
}

redshift_encrypt_key_err = "AWS Redshift Cluster not encrypted using Customer Managed Key" {
    aws_issue["redshift_encrypt_key"]
} else = "AWS Redshift Cluster not encrypted using Customer Managed Key" {
    aws_bool_issue["redshift_encrypt_key"]
}

redshift_encrypt_key_miss_err = "Redshift attribute KmsKeyId missing in the resource" {
    aws_attribute_absence["redshift_encrypt_key"]
}

redshift_encrypt_key_metadata := {
    "Policy Code": "PR-AWS-0133-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Redshift Cluster not encrypted using Customer Managed Key",
    "Policy Description": "This policy identifies Redshift Clusters which are encrypted with default KMS keys and not with Keys managed by Customer. It is a best practice to use customer managed KMS Keys to encrypt your Redshift databases data. Customer-managed CMKs give you more flexibility, including the ability to create, rotate, disable, define access control for, and audit the encryption keys used to help protect your data.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-redshift-cluster.html"
}

#
# PR-AWS-0134-CFR
#

default redshift_public = null

aws_issue["redshift_public"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::redshift::cluster"
    lower(resource.Properties.PubliclyAccessible) == "true"
}

aws_bool_issue["redshift_public"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::redshift::cluster"
    resource.Properties.PubliclyAccessible
}

redshift_public {
    lower(input.Resources[i].Type) == "aws::redshift::cluster"
    not aws_issue["redshift_public"]
    not aws_bool_issue["redshift_public"]
}

redshift_public = false {
    aws_issue["redshift_public"]
}

redshift_public = false {
    aws_bool_issue["redshift_public"]
}

redshift_public_err = "AWS Redshift clusters should not be publicly accessible" {
    aws_issue["redshift_public"]
} error = "AWS Redshift clusters should not be publicly accessible" {
    aws_bool_issue["redshift_public"]
}


redshift_public_metadata := {
    "Policy Code": "PR-AWS-0134-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Redshift clusters should not be publicly accessible",
    "Policy Description": "This policy identifies AWS Redshift clusters which are accessible publicly.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-redshift-cluster.html"
}

#
# PR-AWS-0135-CFR
#

default redshift_audit = null

aws_attribute_absence["redshift_audit"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::redshift::cluster"
    not resource.Properties.LoggingProperties.BucketName
}

aws_issue["redshift_audit"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::redshift::cluster"
    count(resource.Properties.LoggingProperties.BucketName) == 0
}

redshift_audit {
    lower(input.Resources[i].Type) == "aws::redshift::cluster"
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

redshift_audit_miss_err = "Redshift attribute LoggingProperties.BucketName missing in the resource" {
    aws_attribute_absence["redshift_audit"]
}

redshift_audit_metadata := {
    "Policy Code": "PR-AWS-0135-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Redshift database does not have audit logging enabled",
    "Policy Description": "Audit logging is not enabled by default in Amazon Redshift. When you enable logging on your cluster, Amazon Redshift creates and uploads logs to Amazon S3 that capture data from the creation of the cluster to the present time.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-redshift-cluster.html"
}


#
# PR-AWS-0136-CFR
#

default redshift_require_ssl = null

aws_attribute_absence["redshift_require_ssl"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::redshift::clusterparametergroup"
    not resource.Properties.Parameters
}

aws_issue["redshift_require_ssl"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::redshift::clusterparametergroup"
    count([c | lower(resource.Properties.Parameters[_].ParameterName) == "require_ssl"; c := 1]) == 0
}

aws_issue["redshift_require_ssl"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::redshift::clusterparametergroup"
    params = resource.Properties.Parameters[_]
    lower(params.ParameterName) == "require_ssl"
    lower(params.ParameterValue) == "false"
}

redshift_require_ssl {
    lower(input.Resources[i].Type) == "aws::redshift::clusterparametergroup"
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

redshift_require_ssl_miss_err = "Redshift attribute Properties missing in the resource" {
    aws_attribute_absence["redshift_require_ssl"]
}

redshift_require_ssl_metadata := {
    "Policy Code": "PR-AWS-0136-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Redshift does not have require_ssl configured",
    "Policy Description": "This policy identifies Redshift databases in which data connection to and from is occurring on an insecure channel. SSL connections ensures the security of the data in transit.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-redshift-cluster.html"
}

#
# PR-AWS-0137-CFR
#

default redshift_encrypt = null

aws_issue["redshift_encrypt"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::redshift::cluster"
    lower(resource.Properties.Encrypted) == "false"
}

aws_bool_issue["redshift_encrypt"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::redshift::cluster"
    not resource.Properties.Encrypted
}


redshift_encrypt {
    lower(input.Resources[i].Type) == "aws::redshift::cluster"
    not aws_issue["redshift_encrypt"]
    not aws_bool_issue["redshift_encrypt"]
}


redshift_encrypt = false {
    aws_issue["redshift_encrypt"]
}

redshift_encrypt = false {
    aws_bool_issue["redshift_encrypt"]
}

redshift_encrypt_err = "AWS Redshift instances are not encrypted" {
    aws_issue["redshift_encrypt"]
} else = "AWS Redshift instances are not encrypted" {
    aws_bool_issue["redshift_encrypt"]
}

redshift_encrypt_metadata := {
    "Policy Code": "PR-AWS-0137-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Redshift instances are not encrypted",
    "Policy Description": "This policy identifies AWS Redshift instances which are not encrypted. These instances should be encrypted for clusters to help protect data at rest which otherwise can result in a data breach.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-redshift-cluster.html"
}
