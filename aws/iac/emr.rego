package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-securityconfiguration
#
# PR-AWS-0217-CFR
#

default emr_security = null

aws_issue["emr_security"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::emr::cluster"
    not resource.Properties.SecurityConfiguration
}

aws_issue["emr_security"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::emr::cluster"
    count(resource.Properties.SecurityConfiguration) == 0
}

aws_issue["emr_security"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::emr::cluster"
    resource.Properties.SecurityConfiguration == null
}

emr_security {
    lower(input.Resources[i].Type) == "aws::emr::cluster"
    not aws_issue["emr_security"]
}

emr_security = false {
    aws_issue["emr_security"]
}

emr_security = "Ensure AWS EMR cluster is configured with security configuration" {
    aws_issue["emr_security"]
}

emr_security_metadata := {
    "Policy Code": "PR-AWS-0217-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure AWS EMR cluster is configured with security configuration",
    "Policy Description": "Ensure AWS EMR cluster is configured with security configuration",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-securityconfiguration"
}


#
# PR-AWS-0218-CFR
#

default emr_kerberos = null

aws_issue["emr_kerberos"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::emr::cluster"
    not resource.Properties.KerberosAttributes.Realm
}

aws_issue["emr_kerberos"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::emr::cluster"
    resource.Properties.KerberosAttributes.Realm == null
}

aws_issue["emr_kerberos"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::emr::cluster"
    count(resource.Properties.KerberosAttributes.Realm) == 0
}

emr_kerberos {
    lower(input.Resources[i].Type) == "aws::emr::cluster"
    not aws_issue["emr_kerberos"]
}

emr_kerberos = false {
    aws_issue["emr_kerberos"]
}

emr_kerberos = "Must use kerberized auth for internal communications within the cluster" {
    aws_issue["emr_kerberos"]
}

emr_kerberos_metadata := {
    "Policy Code": "PR-AWS-0218-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Must use kerberized auth for internal communications within the cluster",
    "Policy Description": "Must use kerberized auth for internal communications within the cluster",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-kerberosattributes"
}


#
# PR-AWS-0219-CFR
#

default emr_s3_encryption = null

aws_issue["emr_s3_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::emr::securityconfiguration"
    not resource.Properties.SecurityConfiguration.EncryptionConfiguration.AtRestEncryptionConfiguration.S3EncryptionConfiguration.EncryptionMode
}

aws_issue["emr_s3_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::emr::securityconfiguration"
    count(resource.Properties.SecurityConfiguration.EncryptionConfiguration.AtRestEncryptionConfiguration.S3EncryptionConfiguration.EncryptionMode) == 0
}

emr_s3_encryption {
    lower(input.Resources[i].Type) == "aws::emr::securityconfiguration"
    not aws_issue["emr_s3_encryption"]
}

emr_s3_encryption = false {
    aws_issue["emr_s3_encryption"]
}

emr_s3_encryption_err = "Security configuration used with the cluster should have encryption at rest for S3, EBS volume" {
    aws_issue["emr_s3_encryption"]
}

emr_s3_encryption_metadata := {
    "Policy Code": "PR-AWS-0219-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Security configuration used with the cluster should have encryption at rest for S3, EBS volume",
    "Policy Description": "Security configuration used with the cluster should have encryption at rest for S3, EBS volume",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-securityconfiguration"
}


#
# PR-AWS-0220-CFR
#

default emr_local_encryption_cmk = null

aws_issue["emr_local_encryption_cmk"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::emr::securityconfiguration"
    not resource.Properties.SecurityConfiguration.EncryptionConfiguration.AtRestEncryptionConfiguration.LocalDiskEncryptionConfiguration.EncryptionKeyProviderType
}

aws_issue["emr_local_encryption_cmk"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::emr::securityconfiguration"
    count(resource.Properties.SecurityConfiguration.EncryptionConfiguration.AtRestEncryptionConfiguration.LocalDiskEncryptionConfiguration.EncryptionKeyProviderType) == 0
}

aws_issue["emr_local_encryption_cmk"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::emr::securityconfiguration"
    lower(resource.Properties.SecurityConfiguration.EncryptionConfiguration.AtRestEncryptionConfiguration.LocalDiskEncryptionConfiguration.EncryptionKeyProviderType) != "awskms"
}

emr_local_encryption_cmk {
    lower(input.Resources[i].Type) == "aws::emr::securityconfiguration"
    not aws_issue["emr_local_encryption_cmk"]
}

emr_local_encryption_cmk = false {
    aws_issue["emr_local_encryption_cmk"]
}

emr_local_encryption_cmk_err = "Ensure AWS EMR cluster is enabled with local disk encryption using CMK." {
    aws_issue["emr_local_encryption_cmk"]
}

emr_local_encryption_cmk_metadata := {
    "Policy Code": "PR-AWS-0220-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure AWS EMR cluster is enabled with local disk encryption using CMK.",
    "Policy Description": "Ensure AWS EMR cluster is enabled with local disk encryption using CMK.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-securityconfiguration"
}


#
# PR-AWS-0221-CFR
#

default emr_local_encryption = null

aws_issue["emr_local_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::emr::securityconfiguration"
    not resource.Properties.SecurityConfiguration.EncryptionConfiguration.AtRestEncryptionConfiguration.LocalDiskEncryptionConfiguration.EncryptionKeyProviderType
}

aws_issue["emr_local_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::emr::securityconfiguration"
    count(resource.Properties.SecurityConfiguration.EncryptionConfiguration.AtRestEncryptionConfiguration.LocalDiskEncryptionConfiguration.EncryptionKeyProviderType) == 0
}

emr_local_encryption {
    lower(input.Resources[i].Type) == "aws::emr::securityconfiguration"
    not aws_issue["emr_local_encryption"]
}

emr_local_encryption = false {
    aws_issue["emr_local_encryption"]
}

emr_local_encryption_err = "Ensure AWS EMR cluster is enabled with local disk encryption" {
    aws_issue["emr_local_encryption"]
}

emr_local_encryption_metadata := {
    "Policy Code": "PR-AWS-0221-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure AWS EMR cluster is enabled with local disk encryption",
    "Policy Description": "Ensure AWS EMR cluster is enabled with local disk encryption",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-securityconfiguration"
}


#
# PR-AWS-0222-CFR
#

default emr_rest_encryption = null

aws_issue["emr_rest_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::emr::securityconfiguration"
    lower(resource.Properties.SecurityConfiguration.EncryptionConfiguration.EnableAtRestEncryption) == "false"
}

aws_bool_issue["emr_rest_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::emr::securityconfiguration"
    not resource.Properties.SecurityConfiguration.EncryptionConfiguration.EnableAtRestEncryption
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

emr_rest_encryption_err = "Ensure EMR cluster is enabled with data encryption at rest" {
    aws_issue["emr_rest_encryption"]
} else = "Ensure EMR cluster is enabled with data encryption at rest" {
    aws_bool_issue["emr_rest_encryption"]
}

emr_rest_encryption_metadata := {
    "Policy Code": "PR-AWS-0222-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure EMR cluster is enabled with data encryption at rest",
    "Policy Description": "Ensure EMR cluster is enabled with data encryption at rest",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-securityconfiguration"
}



#
# PR-AWS-0223-CFR
#

default emr_s3_encryption_sse = null

aws_issue["emr_s3_encryption_sse"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::emr::securityconfiguration"
    not resource.Properties.SecurityConfiguration.EncryptionConfiguration.AtRestEncryptionConfiguration.S3EncryptionConfiguration.EncryptionMode
}

aws_issue["emr_s3_encryption_sse"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::emr::securityconfiguration"
    count(resource.Properties.SecurityConfiguration.EncryptionConfiguration.AtRestEncryptionConfiguration.S3EncryptionConfiguration.EncryptionMode) == 0
}

aws_issue["emr_s3_encryption_sse"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::emr::securityconfiguration"
    resource.Properties.SecurityConfiguration.EncryptionConfiguration.AtRestEncryptionConfiguration.S3EncryptionConfiguration.EncryptionMode
    lower(resource.Properties.SecurityConfiguration.EncryptionConfiguration.AtRestEncryptionConfiguration.S3EncryptionConfiguration.EncryptionMode) != "sse-kms"
}

emr_s3_encryption_sse {
    lower(input.Resources[i].Type) == "aws::emr::securityconfiguration"
    not aws_issue["emr_s3_encryption_sse"]
}

emr_s3_encryption_sse = false {
    aws_issue["emr_s3_encryption_sse"]
}

emr_s3_encryption_sse_err = "Ensure EMR cluster is configured with SSE KMS for data at rest encryption" {
    aws_issue["emr_s3_encryption_sse"]
}

emr_s3_encryption_sse_metadata := {
    "Policy Code": "PR-AWS-0223-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure EMR cluster is configured with SSE KMS for data at rest encryption",
    "Policy Description": "Ensure EMR cluster is configured with SSE KMS for data at rest encryption",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-securityconfiguration"
}


#
# PR-AWS-0224-CFR
#

default emr_transit_encryption = null

aws_issue["emr_transit_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::emr::securityconfiguration"
    lower(resource.Properties.SecurityConfiguration.EncryptionConfiguration.EnableInTransitEncryption) == "false"
}

aws_bool_issue["emr_transit_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::emr::securityconfiguration"
    not resource.Properties.SecurityConfiguration.EncryptionConfiguration.EnableInTransitEncryption
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

emr_transit_encryption_err = "Ensure EMR cluster is enabled with data encryption in transit" {
    aws_issue["emr_transit_encryption"]
} else = "Ensure EMR cluster is enabled with data encryption in transit" {
    aws_bool_issue["emr_transit_encryption"]
}

emr_transit_encryption_metadata := {
    "Policy Code": "PR-AWS-0224-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure EMR cluster is enabled with data encryption in transit",
    "Policy Description": "Ensure EMR cluster is enabled with data encryption in transit",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-securityconfiguration"
}
