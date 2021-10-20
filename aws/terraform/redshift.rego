package rule


#
# PR-AWS-TRF-RSH-001
#

default redshift_encrypt_key = null

aws_attribute_absence["redshift_encrypt_key"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_redshift_cluster"
    not resource.properties.kms_key_id
}

aws_issue["redshift_encrypt_key"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_redshift_cluster"
    not startswith(lower(resource.properties.kms_key_id), "arn:")
}

aws_issue["redshift_encrypt_key"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_redshift_cluster"
    lower(resource.properties.encrypted) == "false"
}

aws_bool_issue["redshift_encrypt_key"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_redshift_cluster"
    not resource.properties.encrypted
}

redshift_encrypt_key {
    lower(input.resources[_].type) == "aws_redshift_cluster"
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
} else = "Redshift attribute kms_key_id missing in the resource" {
    aws_attribute_absence["redshift_encrypt_key"]
}

redshift_encrypt_key_metadata := {
    "Policy Code": "PR-AWS-TRF-RSH-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Redshift Cluster not encrypted using Customer Managed Key",
    "Policy Description": "This policy identifies Redshift Clusters which are encrypted with default KMS keys and not with Keys managed by Customer. It is a best practice to use customer managed KMS Keys to encrypt your Redshift databases data. Customer-managed CMKs give you more flexibility, including the ability to create, rotate, disable, define access control for, and audit the encryption keys used to help protect your data.",
    "Resource Type": "aws_redshift_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-redshift-cluster.html"
}

#
# PR-AWS-TRF-RSH-002
#

default redshift_public = null

aws_issue["redshift_public"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_redshift_cluster"
    lower(resource.properties.publicly_accessible) == "true"
}

aws_bool_issue["redshift_public"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_redshift_cluster"
    resource.properties.publicly_accessible
}

redshift_public {
    lower(input.resources[_].type) == "aws_redshift_cluster"
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
} else = "AWS Redshift clusters should not be publicly accessible" {
    aws_bool_issue["redshift_public"]
}

redshift_public_metadata := {
    "Policy Code": "PR-AWS-TRF-RSH-002",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Redshift clusters should not be publicly accessible",
    "Policy Description": "This policy identifies AWS Redshift clusters which are accessible publicly.",
    "Resource Type": "aws_redshift_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-redshift-cluster.html"
}

#
# PR-AWS-TRF-RSH-007
#

default redshift_audit = null

aws_attribute_absence["redshift_audit"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_redshift_cluster"
    not resource.properties.logging
}

aws_issue["redshift_audit"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_redshift_cluster"
    count(resource.properties.logging) == 0
}

aws_issue["redshift_audit"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_redshift_cluster"
    logging := resource.properties.logging[_]
    count([c | logging.bucket_name != null; c:= 1]) == 0
}

aws_issue["redshift_audit"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_redshift_cluster"
    logging := resource.properties.logging[_]
    count(logging.bucket_name) == 0
}

redshift_audit {
    lower(input.resources[_].type) == "aws_redshift_cluster"
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
} else = "Redshift attribute logging.bucket_name missing in the resource" {
    aws_attribute_absence["redshift_audit"]
}

redshift_audit_metadata := {
    "Policy Code": "PR-AWS-TRF-RSH-007",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Redshift database does not have audit logging enabled",
    "Policy Description": "Audit logging is not enabled by default in Amazon Redshift. When you enable logging on your cluster, Amazon Redshift creates and uploads logs to Amazon S3 that capture data from the creation of the cluster to the present time.",
    "Resource Type": "aws_redshift_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-redshift-cluster.html"
}

#
# PR-AWS-TRF-RSH-003
#

default redshift_require_ssl = null

aws_attribute_absence["redshift_require_ssl"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_redshift_parameter_group"
    not resource.properties.parameter
}

aws_issue["redshift_require_ssl"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_redshift_parameter_group"
    count([c | lower(resource.properties.parameter[_].name) == "require_ssl"; c := 1]) == 0
}

aws_issue["redshift_require_ssl"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_redshift_parameter_group"
    params = resource.properties.parameter[_]
    lower(params.name) == "require_ssl"
    lower(params.value) == "false"
}

aws_bool_issue["redshift_require_ssl"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_redshift_parameter_group"
    params = resource.properties.parameter[_]
    lower(params.name) == "require_ssl"
    not params.value
}

redshift_require_ssl {
    lower(input.resources[_].type) == "aws_redshift_parameter_group"
    not aws_issue["redshift_require_ssl"]
    not aws_bool_issue["redshift_require_ssl"]
    not aws_attribute_absence["redshift_require_ssl"]
}

redshift_require_ssl = false {
    aws_issue["redshift_require_ssl"]
}

redshift_require_ssl = false {
    aws_bool_issue["redshift_require_ssl"]
}

redshift_require_ssl = false {
    aws_attribute_absence["redshift_require_ssl"]
}

redshift_require_ssl_err = "AWS Redshift does not have require_ssl configured" {
    aws_issue["redshift_require_ssl"]
} else = "AWS Redshift does not have require_ssl configured" {
    aws_bool_issue["redshift_require_ssl"]
} else = "Redshift attribute properties missing in the resource" {
    aws_attribute_absence["redshift_require_ssl"]
}

redshift_require_ssl_metadata := {
    "Policy Code": "PR-AWS-TRF-RSH-003",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Redshift does not have require_ssl configured",
    "Policy Description": "This policy identifies Redshift databases in which data connection to and from is occurring on an insecure channel. SSL connections ensures the security of the data in transit.",
    "Resource Type": "aws_redshift_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-redshift-cluster.html"
}

#
# PR-AWS-TRF-RSH-004
#

default redshift_encrypt = null

aws_issue["redshift_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_redshift_cluster"
    lower(resource.properties.encrypted) == "false"
}

aws_bool_issue["redshift_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_redshift_cluster"
    not resource.properties.encrypted
}

redshift_encrypt {
    lower(input.resources[_].type) == "aws_redshift_cluster"
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
    "Policy Code": "PR-AWS-TRF-RSH-004",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Redshift instances are not encrypted",
    "Policy Description": "This policy identifies AWS Redshift instances which are not encrypted. These instances should be encrypted for clusters to help protect data at rest which otherwise can result in a data breach.",
    "Resource Type": "aws_redshift_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-redshift-cluster.html"
}

#
# PR-AWS-TRF-RSH-005
#

default redshift_allow_version_upgrade = null

aws_issue["redshift_allow_version_upgrade"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_redshift_cluster"
    lower(resource.properties.allow_version_upgrade) == "false"
}

aws_bool_issue["redshift_allow_version_upgrade"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_redshift_cluster"
    not resource.properties.allow_version_upgrade
}


redshift_allow_version_upgrade {
    lower(input.resources[i].type) == "aws_redshift_cluster"
    not aws_issue["redshift_allow_version_upgrade"]
    not aws_bool_issue["redshift_allow_version_upgrade"]
}


redshift_allow_version_upgrade = false {
    aws_issue["redshift_allow_version_upgrade"]
}

redshift_allow_version_upgrade = false {
    aws_bool_issue["redshift_allow_version_upgrade"]
}

redshift_allow_version_upgrade_err = "Ensure Redshift cluster allow version upgrade by default" {
    aws_issue["redshift_allow_version_upgrade"]
} else = "Ensure Redshift cluster allow version upgrade by default" {
    aws_bool_issue["redshift_allow_version_upgrade"]
}

redshift_allow_version_upgrade_metadata := {
    "Policy Code": "PR-AWS-TRF-RSH-005",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure Redshift cluster allow version upgrade by default",
    "Policy Description": "This policy identifies AWS Redshift instances which has not enabled AllowVersionUpgrade. major version upgrades can be applied during the maintenance window to the Amazon Redshift engine that is running on the cluster. When a new major version of the Amazon Redshift engine is released, you can request that the service automatically apply upgrades during the maintenance window to the Amazon Redshift engine that is running on your cluster.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-redshift-cluster.html#cfn-redshift-cluster-allowversionupgrade"
}