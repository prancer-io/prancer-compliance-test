package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-securityconfiguration
#
# PR-AWS-CFR-EMR-001
#

default emr_security = null

aws_issue["emr_security"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::emr::cluster"
    not resource.Properties.SecurityConfiguration
}

source_path[{"emr_security": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::emr::cluster"
    not resource.Properties.SecurityConfiguration
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "SecurityConfiguration"]
        ],
    }
}

aws_issue["emr_security"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::emr::cluster"
    count(resource.Properties.SecurityConfiguration) == 0
}

source_path[{"emr_security": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::emr::cluster"
    count(resource.Properties.SecurityConfiguration) == 0
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "SecurityConfiguration"]
        ],
    }
}

emr_security {
    lower(input.Resources[i].Type) == "aws::emr::cluster"
    not aws_issue["emr_security"]
}

emr_security = false {
    aws_issue["emr_security"]
}

emr_security_err = "AWS EMR cluster is not configured with security configuration" {
    aws_issue["emr_security"]
}

emr_security_metadata := {
    "Policy Code": "PR-AWS-CFR-EMR-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS EMR cluster is not configured with security configuration",
    "Policy Description": "This policy identifies EMR clusters which are not configured with security configuration. With Amazon EMR release version 4.8.0 or later, you can use security configurations to configure data encryption, Kerberos authentication, and Amazon S3 authorization for EMRFS.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-securityconfiguration"
}


#
# PR-AWS-CFR-EMR-002
#

default emr_kerberos = null

aws_issue["emr_kerberos"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::emr::cluster"
    not resource.Properties.KerberosAttributes.Realm
}

source_path[{"emr_security": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::emr::cluster"
    not resource.Properties.KerberosAttributes.Realm
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "KerberosAttributes", "Realm"]
        ],
    }
}

aws_issue["emr_kerberos"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::emr::cluster"
    count(resource.Properties.KerberosAttributes.Realm) == 0
}

source_path[{"emr_security": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::emr::cluster"
    count(resource.Properties.KerberosAttributes.Realm) == 0
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "KerberosAttributes", "Realm"]
        ],
    }
}

emr_kerberos {
    lower(input.Resources[i].Type) == "aws::emr::cluster"
    not aws_issue["emr_kerberos"]
}

emr_kerberos = false {
    aws_issue["emr_kerberos"]
}

emr_kerberos_err = "AWS EMR cluster is not configured with Kerberos Authentication" {
    aws_issue["emr_kerberos"]
}

emr_kerberos_metadata := {
    "Policy Code": "PR-AWS-CFR-EMR-002",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS EMR cluster is not configured with Kerberos Authentication",
    "Policy Description": "This policy identifies EMR clusters which are not configured with Kerberos Authentication. Kerberos uses secret-key cryptography to provide strong authentication so that passwords or other credentials aren't sent over the network in an unencrypted format.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-kerberosattributes"
}


#
# PR-AWS-CFR-EMR-003
#

default emr_s3_encryption = null

aws_issue["emr_s3_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::emr::securityconfiguration"
    not resource.Properties.SecurityConfiguration.EncryptionConfiguration.AtRestEncryptionConfiguration.S3EncryptionConfiguration.EncryptionMode
}

source_path[{"emr_s3_encryption": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::emr::securityconfiguration"
    not resource.Properties.SecurityConfiguration.EncryptionConfiguration.AtRestEncryptionConfiguration.S3EncryptionConfiguration.EncryptionMode
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "SecurityConfiguration", "EncryptionConfiguration", "AtRestEncryptionConfiguration", "S3EncryptionConfiguration", "EncryptionMode"]
        ],
    }
}

aws_issue["emr_s3_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::emr::securityconfiguration"
    count(resource.Properties.SecurityConfiguration.EncryptionConfiguration.AtRestEncryptionConfiguration.S3EncryptionConfiguration.EncryptionMode) == 0
}

source_path[{"emr_s3_encryption": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::emr::securityconfiguration"
    count(resource.Properties.SecurityConfiguration.EncryptionConfiguration.AtRestEncryptionConfiguration.S3EncryptionConfiguration.EncryptionMode) == 0
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "SecurityConfiguration", "EncryptionConfiguration", "AtRestEncryptionConfiguration", "S3EncryptionConfiguration", "EncryptionMode"]
        ],
    }
}

emr_s3_encryption {
    lower(input.Resources[i].Type) == "aws::emr::securityconfiguration"
    not aws_issue["emr_s3_encryption"]
}

emr_s3_encryption = false {
    aws_issue["emr_s3_encryption"]
}

emr_s3_encryption_err = "AWS EMR cluster is not configured with CSE CMK for data at rest encryption (Amazon S3 with EMRFS)" {
    aws_issue["emr_s3_encryption"]
}

emr_s3_encryption_metadata := {
    "Policy Code": "PR-AWS-CFR-EMR-003",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS EMR cluster is not configured with CSE CMK for data at rest encryption (Amazon S3 with EMRFS)",
    "Policy Description": "This policy identifies EMR clusters which are not configured with Client Side Encryption with Customer Master Keys(CSE CMK) for data at rest encryption of Amazon S3 with EMRFS. As a best practice, use Customer Master Keys (CMK) to encrypt the data in your EMR cluster and ensure full control over your data.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-securityconfiguration"
}


#
# PR-AWS-CFR-EMR-004
#

default emr_local_encryption_cmk = null

aws_issue["emr_local_encryption_cmk"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::emr::securityconfiguration"
    not resource.Properties.SecurityConfiguration.EncryptionConfiguration.AtRestEncryptionConfiguration.LocalDiskEncryptionConfiguration.EncryptionKeyProviderType
}

source_path[{"emr_local_encryption_cmk": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::emr::securityconfiguration"
    not resource.Properties.SecurityConfiguration.EncryptionConfiguration.AtRestEncryptionConfiguration.LocalDiskEncryptionConfiguration.EncryptionKeyProviderType
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "SecurityConfiguration", "EncryptionConfiguration", "AtRestEncryptionConfiguration", "LocalDiskEncryptionConfiguration", "EncryptionKeyProviderType"]
        ],
    }
}

aws_issue["emr_local_encryption_cmk"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::emr::securityconfiguration"
    count(resource.Properties.SecurityConfiguration.EncryptionConfiguration.AtRestEncryptionConfiguration.LocalDiskEncryptionConfiguration.EncryptionKeyProviderType) == 0
}

source_path[{"emr_local_encryption_cmk": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::emr::securityconfiguration"
    count(resource.Properties.SecurityConfiguration.EncryptionConfiguration.AtRestEncryptionConfiguration.LocalDiskEncryptionConfiguration.EncryptionKeyProviderType) == 0
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "SecurityConfiguration", "EncryptionConfiguration", "AtRestEncryptionConfiguration", "LocalDiskEncryptionConfiguration", "EncryptionKeyProviderType"]
        ],
    }
}

aws_issue["emr_local_encryption_cmk"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::emr::securityconfiguration"
    lower(resource.Properties.SecurityConfiguration.EncryptionConfiguration.AtRestEncryptionConfiguration.LocalDiskEncryptionConfiguration.EncryptionKeyProviderType) != "awskms"
}

source_path[{"emr_local_encryption_cmk": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::emr::securityconfiguration"
    lower(resource.Properties.SecurityConfiguration.EncryptionConfiguration.AtRestEncryptionConfiguration.LocalDiskEncryptionConfiguration.EncryptionKeyProviderType) != "awskms"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "SecurityConfiguration", "EncryptionConfiguration", "AtRestEncryptionConfiguration", "LocalDiskEncryptionConfiguration", "EncryptionKeyProviderType"]
        ],
    }
}

emr_local_encryption_cmk {
    lower(input.Resources[i].Type) == "aws::emr::securityconfiguration"
    not aws_issue["emr_local_encryption_cmk"]
}

emr_local_encryption_cmk = false {
    aws_issue["emr_local_encryption_cmk"]
}

emr_local_encryption_cmk_err = "AWS EMR cluster is not enabled with local disk encryption" {
    aws_issue["emr_local_encryption_cmk"]
}

emr_local_encryption_cmk_metadata := {
    "Policy Code": "PR-AWS-CFR-EMR-004",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS EMR cluster is not enabled with local disk encryption",
    "Policy Description": "This policy identifies AWS EMR clusters that are not enabled with local disk encryption(Customer Managed Key). Applications using the local file system on each cluster instance for intermediate data throughout workloads, where data could be spilled to disk when it overflows memory. With Local disk encryption at place, data at rest can be protected.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-securityconfiguration"
}


#
# PR-AWS-CFR-EMR-006
#

default emr_rest_encryption = null

aws_issue["emr_rest_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::emr::securityconfiguration"
    lower(resource.Properties.SecurityConfiguration.EncryptionConfiguration.EnableAtRestEncryption) == "false"
}

source_path[{"emr_local_encryption": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::emr::securityconfiguration"
    lower(resource.Properties.SecurityConfiguration.EncryptionConfiguration.EnableAtRestEncryption) == "false"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "SecurityConfiguration", "EncryptionConfiguration", "EnableAtRestEncryption"]
        ],
    }
}

aws_bool_issue["emr_rest_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::emr::securityconfiguration"
    not resource.Properties.SecurityConfiguration.EncryptionConfiguration.EnableAtRestEncryption
}

source_path[{"emr_local_encryption": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::emr::securityconfiguration"
    not resource.Properties.SecurityConfiguration.EncryptionConfiguration.EnableAtRestEncryption
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "SecurityConfiguration", "EncryptionConfiguration", "EnableAtRestEncryption"]
        ],
    }
}

emr_rest_encryption {
    lower(input.Resources[i].Type) == "aws::emr::securityconfiguration"
    not aws_issue["emr_rest_encryption"]
    not aws_bool_issue["emr_rest_encryption"]
}

emr_rest_encryption = false {
    aws_issue["emr_rest_encryption"]
}

emr_rest_encryption = false {
    aws_bool_issue["emr_rest_encryption"]
}

emr_rest_encryption_err = "AWS EMR cluster is not enabled with data encryption at rest" {
    aws_issue["emr_rest_encryption"]
} else = "Ensure EMR cluster is enabled with data encryption at rest" {
    aws_bool_issue["emr_rest_encryption"]
}

emr_rest_encryption_metadata := {
    "Policy Code": "PR-AWS-CFR-EMR-006",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS EMR cluster is not enabled with data encryption at rest",
    "Policy Description": "This policy identifies AWS EMR clusters for which data encryption at rest is not enabled. Encryption of data at rest is required to prevent unauthorized users from accessing the sensitive information available on your  EMR clusters and associated storage systems.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-securityconfiguration"
}

#
# PR-AWS-CFR-EMR-007
#

default emr_transit_encryption = null

aws_issue["emr_transit_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::emr::securityconfiguration"
    lower(resource.Properties.SecurityConfiguration.EncryptionConfiguration.EnableInTransitEncryption) == "false"
}

source_path[{"emr_transit_encryption": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::emr::securityconfiguration"
    lower(resource.Properties.SecurityConfiguration.EncryptionConfiguration.EnableInTransitEncryption) == "false"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "SecurityConfiguration", "EncryptionConfiguration", "EnableInTransitEncryption"]
        ],
    }
}

aws_bool_issue["emr_transit_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::emr::securityconfiguration"
    not resource.Properties.SecurityConfiguration.EncryptionConfiguration.EnableInTransitEncryption
}

source_path[{"emr_transit_encryption": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::emr::securityconfiguration"
    not resource.Properties.SecurityConfiguration.EncryptionConfiguration.EnableInTransitEncryption
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "SecurityConfiguration", "EncryptionConfiguration", "EnableInTransitEncryption"]
        ],
    }
}

emr_transit_encryption {
    lower(input.Resources[i].Type) == "aws::emr::securityconfiguration"
    not aws_issue["emr_transit_encryption"]
    not aws_bool_issue["emr_transit_encryption"]
}

emr_transit_encryption = false {
    aws_issue["emr_transit_encryption"]
}

emr_transit_encryption = false {
    aws_bool_issue["emr_transit_encryption"]
}

emr_transit_encryption_err = "AWS EMR cluster is not enabled with data encryption in transit" {
    aws_issue["emr_transit_encryption"]
} else = "AWS EMR cluster is not enabled with data encryption in transit" {
    aws_bool_issue["emr_transit_encryption"]
}

emr_transit_encryption_metadata := {
    "Policy Code": "PR-AWS-CFR-EMR-007",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS EMR cluster is not enabled with data encryption in transit",
    "Policy Description": "This policy identifies AWS EMR clusters which are not enabled with data encryption in transit. It is highly recommended to implement in-transit encryption in order to protect data from unauthorized access as it travels through the network, between clients and storage server. Enabling data encryption in-transit helps prevent unauthorized users from reading sensitive data between your EMR clusters and their associated storage systems.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-securityconfiguration"
}


#
# PR-AWS-CFR-EMR-008
#

default emr_cluster_level_logging = null

aws_issue["emr_cluster_level_logging"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::emr::cluster"
    not resource.Properties.LogUri
}

emr_cluster_level_logging {
    lower(input.Resources[i].Type) == "aws::emr::cluster"
    not aws_issue["emr_cluster_level_logging"]
}

emr_cluster_level_logging = false {
    aws_issue["emr_cluster_level_logging"]
}

emr_cluster_level_logging_err = "Ensure Cluster level logging is enabled for EMR." {
    aws_issue["emr_cluster_level_logging"]
}

emr_cluster_level_logging_metadata := {
    "Policy Code": "PR-AWS-CFR-EMR-008",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure Cluster level logging is enabled for EMR.",
    "Policy Description": "It checks if cluster level logging is enabled for EMR cluster created. This determines whether Amazon EMR captures detailed log data to Amazon S3.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html"
}


#
# PR-AWS-CFR-EMR-009
#

default emr_cluster_not_visible_to_all_iam_users = null

aws_issue["emr_cluster_not_visible_to_all_iam_users"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::emr::cluster"
    resource.Properties.VisibleToAllUsers == true
}

emr_cluster_not_visible_to_all_iam_users {
    lower(input.Resources[i].Type) == "aws::emr::cluster"
    not aws_issue["emr_cluster_not_visible_to_all_iam_users"]
}

emr_cluster_not_visible_to_all_iam_users = false {
    aws_issue["emr_cluster_not_visible_to_all_iam_users"]
}

emr_cluster_not_visible_to_all_iam_users_err = "Ensure EMR cluster is not visible to all IAM users." {
    aws_issue["emr_cluster_not_visible_to_all_iam_users"]
}

emr_cluster_not_visible_to_all_iam_users_metadata := {
    "Policy Code": "PR-AWS-CFR-EMR-009",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure EMR cluster is not visible to all IAM users.",
    "Policy Description": "It checks if the EMR cluster created has a wide visibility to all IAM users. When true, IAM principals in the AWS account can perform EMR cluster actions that their IAM policies allow.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html"
}