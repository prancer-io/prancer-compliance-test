package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-redshift-cluster.html
# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-redshift-clusterparametergroup.html

#
# PR-AWS-CFR-RSH-001
#

default redshift_encrypt_key = true

redshift_encrypt_key = false {
    # lower(resource.Type) == "aws::redshift::cluster"
    Clusters := input.Clusters[_]
    not Clusters.KmsKeyId
}

redshift_encrypt_key = false {
    # lower(resource.Type) == "aws::redshift::cluster"
    Clusters := input.Clusters[_]
    count(Clusters.KmsKeyId) == 0
}

redshift_encrypt_key = false {
    # lower(resource.Type) == "aws::redshift::cluster"
    Clusters := input.Clusters[_]
    not startswith(lower(Clusters.KmsKeyId), "arn:")
}

redshift_encrypt_key = false {
    # lower(resource.Type) == "aws::redshift::cluster"
    Clusters := input.Clusters[_]
    not Clusters.Encrypted
}

redshift_encrypt_key_err = "AWS Redshift Cluster not encrypted using Customer Managed Key" {
    not redshift_encrypt_key
}

redshift_encrypt_key_metadata := {
    "Policy Code": "PR-AWS-CFR-RSH-001",
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
# PR-AWS-CFR-RSH-002
#

default redshift_public = true

redshift_public = false {
    # lower(resource.Type) == "aws::redshift::cluster"
    Clusters := input.Clusters[_]
    Clusters.PubliclyAccessible == true
}

redshift_public_err = "AWS Redshift clusters should not be publicly accessible" {
    not redshift_public
}

redshift_public_metadata := {
    "Policy Code": "PR-AWS-CFR-RSH-002",
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
# PR-AWS-CFR-RSH-003
#

default redshift_require_ssl = true

redshift_require_ssl = false {
    # lower(resource.Type) == "aws::redshift::clusterparametergroup"
    not input.Parameters
}

redshift_require_ssl = false {
    # lower(resource.Type) == "aws::redshift::clusterparametergroup"
    count([c | lower(input.Parameters[_].ParameterName) == "require_ssl"; c := 1]) == 0
}

redshift_require_ssl = false {
    # lower(resource.Type) == "aws::redshift::clusterparametergroup"
    params = input.Parameters[j]
    lower(params.ParameterName) == "require_ssl"
    lower(params.ParameterValue) == "false"
}

redshift_require_ssl_err = "AWS Redshift does not have require_ssl configured" {
    not redshift_require_ssl
}

redshift_require_ssl_metadata := {
    "Policy Code": "PR-AWS-CFR-RSH-003",
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
# PR-AWS-CFR-RSH-004
#

default redshift_encrypt = true

redshift_encrypt = false {
    # lower(resource.Type) == "aws::redshift::cluster"
    Clusters := input.Clusters[_]
    not Clusters.Encrypted
}

redshift_encrypt_err = "AWS Redshift instances are not encrypted" {
    not redshift_encrypt
}

redshift_encrypt_metadata := {
    "Policy Code": "PR-AWS-CFR-RSH-004",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Redshift instances are not encrypted",
    "Policy Description": "This policy identifies AWS Redshift instances which are not encrypted. These instances should be encrypted for clusters to help protect data at rest which otherwise can result in a data breach.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-redshift-cluster.html"
}


#
# PR-AWS-CFR-RSH-005
#

default redshift_allow_version_upgrade = true

redshift_allow_version_upgrade = false {
    # lower(resource.Type) == "aws::redshift::cluster"
    Clusters := input.Clusters[_]
    not Clusters.AllowVersionUpgrade
}

redshift_allow_version_upgrade_err = "Ensure Redshift cluster allow version upgrade by default" {
    not redshift_allow_version_upgrade
}

redshift_allow_version_upgrade_metadata := {
    "Policy Code": "PR-AWS-CFR-RSH-005",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure Redshift cluster allow version upgrade by default",
    "Policy Description": "This policy identifies AWS Redshift instances which has not enabled AllowVersionUpgrade. major version upgrades can be applied during the maintenance window to the Amazon Redshift engine that is running on the cluster. When a new major version of the Amazon Redshift engine is released, you can request that the service automatically apply upgrades during the maintenance window to the Amazon Redshift engine that is running on your cluster.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-redshift-cluster.html#cfn-redshift-cluster-allowversionupgrade"
}


#
# PR-AWS-CFR-RSH-006
#

default redshift_deploy_vpc = true

redshift_allow_version_upgrade = false {
    # lower(resource.Type) == "aws::redshift::cluster"
    Clusters := input.Clusters[_]
    count(Clusters.ClusterSubnetGroupName) == 0
}

redshift_allow_version_upgrade = false {
    # lower(resource.Type) == "aws::redshift::cluster"
    Clusters := input.Clusters[_]
    Clusters.ClusterSubnetGroupName == null
}

redshift_allow_version_upgrade = false {
    # lower(resource.Type) == "aws::redshift::cluster"
    Clusters := input.Clusters[_]
    not Clusters.ClusterSubnetGroupName
}

redshift_deploy_vpc_err = "Ensure Redshift is not deployed outside of a VPC" {
    not redshift_allow_version_upgrade
}

redshift_deploy_vpc_metadata := {
    "Policy Code": "PR-AWS-CFR-RSH-006",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure Redshift is not deployed outside of a VPC",
    "Policy Description": "Ensure that your Redshift clusters are provisioned within the AWS EC2-VPC platform instead of EC2-Classic platform (outdated) for better flexibility and control over clusters security, traffic routing, availability and more.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-redshift-cluster.html#cfn-redshift-cluster-clustersubnetgroupname"
}


#
# PR-AWS-CFR-RSH-007
#

default redshift_audit = true

redshift_audit = false {
    # lower(resource.Type) == "aws::redshift::cluster"
    Clusters := input.Clusters[_]
    not Clusters.LoggingProperties.BucketName
}

redshift_audit = false {
    # lower(resource.Type) == "aws::redshift::cluster"
    Clusters := input.Clusters[_]
    count(Clusters.LoggingProperties.BucketName) == 0
}

redshift_audit_err = "AWS Redshift database does not have audit logging enabled" {
    not redshift_audit
}

redshift_audit_metadata := {
    "Policy Code": "PR-AWS-CFR-RSH-007",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Redshift database does not have audit logging enabled",
    "Policy Description": "Audit logging is not enabled by default in Amazon Redshift. When you enable logging on your cluster, Amazon Redshift creates and uploads logs to Amazon S3 that capture data from the creation of the cluster to the present time.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-redshift-cluster.html"
}
