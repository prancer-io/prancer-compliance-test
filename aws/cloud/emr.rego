package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-securityconfiguration

available_true_choices := ["true", true]
available_false_choices := ["false", false]

#
# PR-AWS-CLD-EMR-001
#

default emr_security = true

emr_security = false {
    # lower(resource.Type) == "aws::emr::cluster"
    not input.SecurityConfiguration
}

emr_security = false{
    # lower(resource.Type) == "aws::emr::cluster"
    count(input.SecurityConfiguration) == 0
}

emr_security_err = "AWS EMR cluster is not configured with security configuration" {
    not emr_security
}

emr_security_metadata := {
    "Policy Code": "PR-AWS-CLD-EMR-001",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS EMR cluster is not configured with security configuration",
    "Policy Description": "This policy identifies EMR clusters which are not configured with security configuration. With Amazon EMR release version 4.8.0 or later, you can use security configurations to configure data encryption, Kerberos authentication, and Amazon S3 authorization for EMRFS.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-securityconfiguration"
}


#
# PR-AWS-CLD-EMR-002
#

default emr_kerberos = true

emr_kerberos = false {
    # lower(resource.Type) == "aws::emr::cluster"
    not input.Cluster.KerberosAttributes.Realm
}

emr_kerberos = false {
    # lower(resource.Type) == "aws::emr::cluster"
    count(input.Cluster.KerberosAttributes.Realm) == 0
}

emr_kerberos_err = "AWS EMR cluster is not configured with Kerberos Authentication" {
    not emr_kerberos
}

emr_kerberos_metadata := {
    "Policy Code": "PR-AWS-CLD-EMR-002",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS EMR cluster is not configured with Kerberos Authentication",
    "Policy Description": "This policy identifies EMR clusters which are not configured with Kerberos Authentication. Kerberos uses secret-key cryptography to provide strong authentication so that passwords or other credentials aren't sent over the network in an unencrypted format.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-kerberosattributes"
}


#
# PR-AWS-CLD-EMR-003
#

default emr_s3_encryption = true

emr_s3_encryption = false {
    # lower(resource.Type) == "aws::emr::securityconfiguration"
    SecurityConfiguration := json.unmarshal(input.SecurityConfiguration)
    not SecurityConfiguration.EncryptionConfiguration.AtRestEncryptionConfiguration.S3EncryptionConfiguration.EncryptionMode
}

emr_s3_encryption = false {
    # lower(resource.Type) == "aws::emr::securityconfiguration"
    SecurityConfiguration := json.unmarshal(input.SecurityConfiguration)
    count(SecurityConfiguration.EncryptionConfiguration.AtRestEncryptionConfiguration.S3EncryptionConfiguration.EncryptionMode) == 0
}

emr_s3_encryption_err = "AWS EMR cluster is not configured with CSE CMK for data at rest encryption (Amazon S3 with EMRFS)" {
    not emr_s3_encryption
}

emr_s3_encryption_metadata := {
    "Policy Code": "PR-AWS-CLD-EMR-003",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS EMR cluster is not configured with CSE CMK for data at rest encryption (Amazon S3 with EMRFS)",
    "Policy Description": "This policy identifies EMR clusters which are not configured with Client Side Encryption with Customer Master Keys(CSE CMK) for data at rest encryption of Amazon S3 with EMRFS. As a best practice, use Customer Master Keys (CMK) to encrypt the data in your EMR cluster and ensure full control over your data.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-securityconfiguration"
}


#
# PR-AWS-CLD-EMR-004
#

default emr_local_encryption_cmk = true

emr_local_encryption_cmk = false {
    # lower(resource.Type) == "aws::emr::securityconfiguration"
    not input.SecurityConfiguration.EncryptionConfiguration.AtRestEncryptionConfiguration.LocalDiskEncryptionConfiguration.EncryptionKeyProviderType
}


emr_local_encryption_cmk = false {
    # lower(resource.Type) == "aws::emr::securityconfiguration"
    count(input.SecurityConfiguration.EncryptionConfiguration.AtRestEncryptionConfiguration.LocalDiskEncryptionConfiguration.EncryptionKeyProviderType) == 0
}

emr_local_encryption_cmk = false {
    # lower(resource.Type) == "aws::emr::securityconfiguration"
    lower(input.SecurityConfiguration.EncryptionConfiguration.AtRestEncryptionConfiguration.LocalDiskEncryptionConfiguration.EncryptionKeyProviderType) != "awskms"
}

emr_local_encryption_cmk_err = "AWS EMR cluster is not enabled with local disk encryption" {
    not emr_local_encryption_cmk
}

emr_local_encryption_cmk_metadata := {
    "Policy Code": "PR-AWS-CLD-EMR-004",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS EMR cluster is not enabled with local disk encryption",
    "Policy Description": "This policy identifies AWS EMR clusters that are not enabled with local disk encryption(Customer Managed Key). Applications using the local file system on each cluster instance for intermediate data throughout workloads, where data could be spilled to disk when it overflows memory. With Local disk encryption at place, data at rest can be protected.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-securityconfiguration"
}


#
# PR-AWS-CLD-EMR-006
#

default emr_rest_encryption = true

emr_rest_encryption = false {
    # lower(resource.Type) == "aws::emr::securityconfiguration"
    not input.SecurityConfiguration.EncryptionConfiguration.EnableAtRestEncryption
}

emr_rest_encryption_err = "AWS EMR cluster is not enabled with data encryption at rest" {
    not emr_rest_encryption
}

emr_rest_encryption_metadata := {
    "Policy Code": "PR-AWS-CLD-EMR-006",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS EMR cluster is not enabled with data encryption at rest",
    "Policy Description": "This policy identifies AWS EMR clusters for which data encryption at rest is not enabled. Encryption of data at rest is required to prevent unauthorized users from accessing the sensitive information available on your  EMR clusters and associated storage systems.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-securityconfiguration"
}

#
# PR-AWS-CLD-EMR-007
#

default emr_transit_encryption = true

emr_transit_encryption = false {
    # lower(resource.Type) == "aws::emr::securityconfiguration"
    not input.SecurityConfiguration.EncryptionConfiguration.EnableInTransitEncryption
}

emr_transit_encryption_err = "AWS EMR cluster is not enabled with data encryption in transit" {
    not emr_transit_encryption
}

emr_transit_encryption_metadata := {
    "Policy Code": "PR-AWS-CLD-EMR-007",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS EMR cluster is not enabled with data encryption in transit",
    "Policy Description": "This policy identifies AWS EMR clusters which are not enabled with data encryption in transit. It is highly recommended to implement in-transit encryption in order to protect data from unauthorized access as it travels through the network, between clients and storage server. Enabling data encryption in-transit helps prevent unauthorized users from reading sensitive data between your EMR clusters and their associated storage systems.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-securityconfiguration"
}

#
# PR-AWS-CLD-EMR-008
#

default emr_cluster_level_logging = true

emr_cluster_level_logging = false {
    # lower(resource.Type) == "aws::emr::cluster"
    not input.Cluster.LogUri
}

emr_cluster_level_logging_err = "Ensure Cluster level logging is enabled for EMR." {
    not emr_cluster_level_logging
}

emr_cluster_level_logging_metadata := {
    "Policy Code": "PR-AWS-CLD-EMR-008",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure Cluster level logging is enabled for EMR.",
    "Policy Description": "It checks if cluster level logging is enabled for EMR cluster created. This determines whether Amazon EMR captures detailed log data to Amazon S3.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/emr.html#EMR.Client.describe_cluster"
}

#
# PR-AWS-CLD-EMR-009
#

default emr_cluster_not_visible_to_all_iam_users = true

emr_cluster_not_visible_to_all_iam_users = false {
    # lower(resource.Type) == "aws::emr::cluster"
    lower(input.Cluster.VisibleToAllUsers) == available_true_choices[_]
}

emr_cluster_not_visible_to_all_iam_users_err = "Ensure EMR cluster is not visible to all IAM users." {
    not emr_cluster_not_visible_to_all_iam_users
}

emr_cluster_not_visible_to_all_iam_users_metadata := {
    "Policy Code": "PR-AWS-CLD-EMR-009",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure EMR cluster is not visible to all IAM users.",
    "Policy Description": "It checks if the EMR cluster created has a wide visibility to all IAM users. When true, IAM principals in the AWS account can perform EMR cluster actions that their IAM policies allow.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/emr.html#EMR.Client.describe_cluster"
}

#
# PR-AWS-CLD-EMR-010
#

default emr_termination_protection_is_enabled = true

emr_termination_protection_is_enabled = false {
    # lower(resource.Type) == "aws::emr::cluster"
    lower(input.Cluster.TerminationProtected) == available_false_choices[_]
}

emr_termination_protection_is_enabled_err = "Ensure Termination protection is enabled for instances in the cluster for EMR." {
    not emr_termination_protection_is_enabled
}

emr_termination_protection_is_enabled_metadata := {
    "Policy Code": "PR-AWS-CLD-EMR-010",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure Termination protection is enabled for instances in the cluster for EMR.",
    "Policy Description": "It checks if the EC2 instances created in EMR cluster are protected against accidental termination.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/emr.html#EMR.Client.describe_cluster"
}

#
# PR-AWS-CLD-EMR-011
#

default emr_block_public_access = true

emr_block_public_access = false {
    # lower(resource.Type) == "aws::emr::cluster"
    lower(input.BlockPublicAccessConfiguration.BlockPublicSecurityGroupRules) == available_false_choices[_]
}

emr_block_public_access_err = "Ensure AWS EMR block public access setting is not disabled." {
    not emr_block_public_access
}

emr_block_public_access_metadata := {
    "Policy Code": "PR-AWS-CLD-EMR-011",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS EMR block public access setting is not disabled.",
    "Policy Description": "This policy identifies AWS EMR which has a disabled block public access setting. AWS EMR block public access prevents a cluster in a public subnet from launching when any security group associated with the cluster has a rule that allows inbound traffic from the internet, unless the port has been specified as an exception. It is recommended to enable AWS EMR Block public access in each AWS Region for your AWS account.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/emr.html#EMR.Client.get_block_public_access_configuration"
}