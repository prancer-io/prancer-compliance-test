package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-msk-cluster.html
#
# PR-AWS-0238-CFR
#
default msk_encryption_at_rest = null

aws_issue["msk_encryption_at_rest"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::msk::cluster"
    not resource.Properties.EncryptionInfo.EncryptionAtRest
}

msk_encryption_at_rest {
    lower(input.Resources[i].Type) == "aws::msk::cluster"
    not aws_issue["msk_encryption_at_rest"]
}

msk_encryption_at_rest = false {
    aws_issue["msk_encryption_at_rest"]
}

msk_encryption_at_rest_err = "Ensure MSK cluster encryption at rest is enabled" {
    aws_issue["msk_encryption_at_rest"]
}


msk_encryption_at_rest_metadata := {
    "Policy Code": "PR-AWS-0238-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure MSK cluster encryption at rest is enabled",
    "Policy Description": "Amazon MSK integrates with AWS Key Management Service (KMS) for server-side encryption. When you create an MSK cluster, you can specify the AWS KMS CMK for Amazon MSK to use to encrypt your data at rest. If you don't specify a CMK, Amazon MSK creates an AWS managed CMK for you and uses it on your behalf.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-msk-cluster.html#cfn-msk-cluster-encryptioninfo"
}


#
# PR-AWS-0239-CFR
#
default msk_encryption_at_rest_cmk = null

aws_issue["msk_encryption_at_rest_cmk"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::msk::cluster"
    not resource.Properties.EncryptionInfo.EncryptionAtRest.DataVolumeKMSKeyId
}

aws_issue["msk_encryption_at_rest_cmk"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::msk::cluster"
    count(resource.Properties.EncryptionInfo.EncryptionAtRest.DataVolumeKMSKeyId) == 0
}

aws_issue["msk_encryption_at_rest_cmk"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::msk::cluster"
    resource.Properties.EncryptionInfo.EncryptionAtRest.DataVolumeKMSKeyId == null
}

msk_encryption_at_rest_cmk {
    lower(input.Resources[i].Type) == "aws::msk::cluster"
    not aws_issue["msk_encryption_at_rest_cmk"]
}

msk_encryption_at_rest_cmk = false {
    aws_issue["msk_encryption_at_rest_cmk"]
}

msk_encryption_at_rest_cmk_err = "Use KMS Customer Master Keys for AWS MSK Clusters" {
    aws_issue["msk_encryption_at_rest_cmk"]
}


msk_encryption_at_rest_cmk_metadata := {
    "Policy Code": "PR-AWS-0239-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Use KMS Customer Master Keys for AWS MSK Clusters",
    "Policy Description": "Ensure that Amazon Managed Streaming for Kafka (MSK) clusters are using AWS KMS Customer Master Keys (CMKs) instead of AWS managed-keys (i.e. default keys) for data encryption, in order to have a fine-grained control over data-at-rest encryption/decryption process and meet compliance requirements. MSK is a fully managed AWS service that enables you to migrate, build and run real-time streaming applications on Apache Kafka.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-msk-cluster.html#cfn-msk-cluster-encryptioninfo"
}

#
# PR-AWS-0240-CFR
#
default msk_in_transit_encryption = null

aws_bool_issue["msk_in_transit_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::msk::cluster"
    not resource.Properties.EncryptionInfo.EncryptionInTransit.InCluster
}

aws_issue["msk_in_transit_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::msk::cluster"
    lower(resource.Properties.EncryptionInfo.EncryptionInTransit.InCluster) == "false"
}

msk_in_transit_encryption {
    lower(input.Resources[i].Type) == "aws::msk::cluster"
    not aws_issue["msk_in_transit_encryption"]
    not aws_bool_issue["msk_in_transit_encryption"]
}

msk_in_transit_encryption = false {
    aws_issue["msk_in_transit_encryption"]
}

msk_in_transit_encryption = false {
    aws_bool_issue["msk_in_transit_encryption"]
}


msk_in_transit_encryption_err = "Ensure data is Encrypted in transit (TLS)" {
    aws_issue["msk_in_transit_encryption"]
} else = "Ensure data is Encrypted in transit (TLS)" {
    aws_bool_issue["msk_in_transit_encryption"]
}


msk_in_transit_encryption_metadata := {
    "Policy Code": "PR-AWS-0240-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure data is Encrypted in transit (TLS)",
    "Policy Description": "Ensure data is Encrypted in transit (TLS)",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-msk-cluster.html#cfn-msk-cluster-encryptioninfo"
}


#
# PR-AWS-0241-CFR
#
default msk_in_transit_encryption_tls = null

aws_bool_issue["msk_in_transit_encryption_tls"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::msk::cluster"
    not resource.Properties.EncryptionInfo.EncryptionInTransit.ClientBroker
}

aws_issue["msk_in_transit_encryption_tls"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::msk::cluster"
    lower(resource.Properties.EncryptionInfo.EncryptionInTransit.ClientBroker) != "tls"
}

msk_in_transit_encryption_tls {
    lower(input.Resources[i].Type) == "aws::msk::cluster"
    not aws_issue["msk_in_transit_encryption_tls"]
    not aws_bool_issue["msk_in_transit_encryption_tls"]
}

msk_in_transit_encryption_tls = false {
    aws_issue["msk_in_transit_encryption_tls"]
}

msk_in_transit_encryption_tls = false {
    aws_bool_issue["msk_in_transit_encryption_tls"]
}


msk_in_transit_encryption_tls_err = "Ensure client authentication is enabled with TLS (mutual TLS authentication)" {
    aws_issue["msk_in_transit_encryption_tls"]
} else = "Ensure client authentication is enabled with TLS (mutual TLS authentication)" {
    aws_bool_issue["msk_in_transit_encryption_tls"]
}


msk_in_transit_encryption_tls_metadata := {
    "Policy Code": "PR-AWS-0241-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure client authentication is enabled with TLS (mutual TLS authentication)",
    "Policy Description": "Enable TLS by setting EncryptionInfo.EncryptionInTransit.ClientBroker value to 'TLS'. to provide trasport layes security to MSK instance",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-msk-cluster.html#cfn-msk-cluster-encryptioninfo"
}


#
# PR-AWS-0242-CFR
#
default msk_vpc = null

aws_issue["msk_vpc"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::msk::cluster"
    not resource.Properties.BrokerNodeGroupInfo.ClientSubnets
}

aws_issue["msk_vpc"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::msk::cluster"
    count(resource.Properties.BrokerNodeGroupInfo.ClientSubnets) == 0
}

msk_vpc {
    lower(input.Resources[i].Type) == "aws::msk::cluster"
    not aws_issue["msk_vpc"]
}

msk_vpc = false {
    aws_issue["msk_vpc"]
}


msk_vpc_err = "Ensure MSK cluster is setup in GS VPC" {
    aws_issue["msk_vpc"]
}


msk_vpc_metadata := {
    "Policy Code": "PR-AWS-0242-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure MSK cluster is setup in GS VPC",
    "Policy Description": "To Add MKS Cluster in gs VPC,Specify exactly two subnets if you are using the US West (N. California) Region. For other Regions where Amazon MSK is available, you can specify either two or three subnets. The subnets that you specify must be in distinct Availability Zones. When you create a cluster, Amazon MSK distributes the broker nodes evenly across the subnets that you specify.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-msk-cluster.html#cfn-msk-cluster-encryptioninfo"
}