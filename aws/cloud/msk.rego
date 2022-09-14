package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-msk-cluster.html

#
# PR-AWS-CLD-MSK-001
#
default msk_encryption_at_rest_cmk = true

msk_encryption_at_rest_cmk = false {
    # lower(resource.Type) == "aws::msk::cluster"
    not input.ClusterInfo.EncryptionInfo.EncryptionAtRest.DataVolumeKMSKeyId
}

msk_encryption_at_rest_cmk = false {
    # lower(resource.Type) == "aws::msk::cluster"
    count(input.ClusterInfo.EncryptionInfo.EncryptionAtRest.DataVolumeKMSKeyId) == 0
}

msk_encryption_at_rest_cmk_err = "Use KMS Customer Master Keys for AWS MSK Clusters" {
    not msk_encryption_at_rest_cmk
}

msk_encryption_at_rest_cmk_metadata := {
    "Policy Code": "PR-AWS-CLD-MSK-001",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Use KMS Customer Master Keys for AWS MSK Clusters",
    "Policy Description": "Ensure that Amazon Managed Streaming for Kafka (MSK) clusters are using AWS KMS Customer Master Keys (CMKs) instead of AWS managed-keys (i.e. default keys) for data encryption, in order to have a fine-grained control over data-at-rest encryption/decryption process and meet compliance requirements. MSK is a fully managed AWS service that enables you to migrate, build and run real-time streaming applications on Apache Kafka.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-msk-cluster.html#cfn-msk-cluster-encryptioninfo"
}

#
# PR-AWS-CLD-MSK-002
#
default msk_in_transit_encryption = true

msk_in_transit_encryption = false {
    # lower(resource.Type) == "aws::msk::cluster"
    not input.ClusterInfo.EncryptionInfo.EncryptionInTransit.InCluster
}

msk_in_transit_encryption_err = "Ensure data is Encrypted in transit (TLS)" {
    not msk_in_transit_encryption
}

msk_in_transit_encryption_metadata := {
    "Policy Code": "PR-AWS-CLD-MSK-002",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure data is Encrypted in transit (TLS)",
    "Policy Description": "Ensure data is Encrypted in transit (TLS)",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-msk-cluster.html#cfn-msk-cluster-encryptioninfo"
}


#
# PR-AWS-CLD-MSK-003
#
default msk_in_transit_encryption_tls = true

msk_in_transit_encryption_tls = false {
    # lower(resource.Type) == "aws::msk::cluster"
    not input.ClusterInfo.EncryptionInfo.EncryptionInTransit.ClientBroker
}

msk_in_transit_encryption_tls = false {
    # lower(resource.Type) == "aws::msk::cluster"
    lower(input.ClusterInfo.EncryptionInfo.EncryptionInTransit.ClientBroker) != "tls"
}

msk_in_transit_encryption_tls_err = "Ensure client authentication is enabled with TLS (mutual TLS authentication)" {
    not msk_in_transit_encryption_tls
}

msk_in_transit_encryption_tls_metadata := {
    "Policy Code": "PR-AWS-CLD-MSK-003",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure client authentication is enabled with TLS (mutual TLS authentication)",
    "Policy Description": "Enable TLS by setting EncryptionInfo.EncryptionInTransit.ClientBroker value to 'TLS'. to provide trasport layes security to MSK instance",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-msk-cluster.html#cfn-msk-cluster-encryptioninfo"
}


#
# PR-AWS-CLD-MSK-004
#
default msk_vpc = true

msk_vpc = false {
    # lower(resource.Type) == "aws::msk::cluster"
    not input.ClusterInfo.BrokerNodeGroupInfo.ClientSubnets
}

msk_vpc = false {
    # lower(resource.Type) == "aws::msk::cluster"
    count(input.ClusterInfo.BrokerNodeGroupInfo.ClientSubnets) == 0
}

msk_vpc_err = "Ensure MSK cluster is setup in GS VPC" {
    not msk_vpc
}

msk_vpc_metadata := {
    "Policy Code": "PR-AWS-CLD-MSK-004",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure MSK cluster is setup in GS VPC",
    "Policy Description": "To Add MKS Cluster in gs VPC,Specify exactly two subnets if you are using the US West (N. California) Region. For other Regions where Amazon MSK is available, you can specify either two or three subnets. The subnets that you specify must be in distinct Availability Zones. When you create a cluster, Amazon MSK distributes the broker nodes evenly across the subnets that you specify.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-msk-cluster.html#cfn-msk-cluster-encryptioninfo"
}


#
# PR-AWS-CLD-MSK-005
#
default msk_cluster_logging_enable = true

msk_cluster_logging_enable = false {
    # lower(resource.Type) == "aws::msk::cluster"
    not input.ClusterInfo.LoggingInfo.BrokerLogs
}

msk_cluster_logging_enable_err = "Ensure Amazon MSK cluster has logging enabled" {
    not msk_cluster_logging_enable
}

msk_cluster_logging_enable_metadata := {
    "Policy Code": "PR-AWS-CLD-MSK-005",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure Amazon MSK cluster has logging enabled",
    "Policy Description": "Consistent cluster logging helps you determine if a request was made with root or AWS Identity and Access Management (IAM) user credentials and whether the request was made with temporary security credentials for a role or federated user.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-brokerlogs.html#cfn-msk-cluster-brokerlogs-cloudwatchlogs"
}

#
# PR-AWS-CLD-MSK-006
#

default msk_cluster_enhanced_monitoring_enable = true

msk_cluster_enhanced_monitoring_enable = false {
    # lower(resource.Type) == "aws::msk::cluster"
    lower(input.ClusterInfo.EnhancedMonitoring) == "default"
}

msk_cluster_enhanced_monitoring_enable = false {
    # lower(resource.Type) == "aws::msk::cluster"
    input.ClusterInfo.EnhancedMonitoring == ""
}

msk_cluster_enhanced_monitoring_enable = false {
    # lower(resource.Type) == "aws::msk::cluster"
    input.ClusterInfo.EnhancedMonitoring == null
}

msk_cluster_enhanced_monitoring_enable_err = "Ensure enhanaced monitoring for AWS MSK is not set to default." {
    not msk_cluster_enhanced_monitoring_enable
}

msk_cluster_enhanced_monitoring_enable_metadata := {
    "Policy Code": "PR-AWS-CLD-MSK-006",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure enhanaced monitoring for AWS MSK is not set to default.",
    "Policy Description": "It is used to check that enhanced monitoring is configured to gather Apache Kafka metrics and sends them to Amazon CloudWatch.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/kafka.html#Kafka.Client.describe_cluster"
}

#
# PR-AWS-CLD-MSK-007
#

default msk_public_access = true

msk_public_access = false {
    # lower(resource.Type) == "aws::msk::cluster"
    lower(input.ClusterInfo.BrokerNodeGroupInfo.ConnectivityInfo.PublicAccess.Type) != "disabled"
}

msk_public_access_err = "Ensure public access is disabled for AWS MSK." {
    not msk_public_access
}

msk_public_access_metadata := {
    "Policy Code": "PR-AWS-CLD-MSK-007",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure public access is disabled for AWS MSK.",
    "Policy Description": "It check whether public access is turned on to the brokers of MSK clusters.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/kafka.html#Kafka.Client.describe_cluster"
}


#
# PR-AWS-CLD-MSK-008
# aws::msk::cluster
# aws::kms::key

default msk_data_is_encrypted = true

msk_data_is_encrypted = false {
    X := input.TEST_MSK[_]
    Y := input.TEST_KMS[_]
    X.ClusterInfo.EncryptionInfo.EncryptionAtRest.DataVolumeKMSKeyId == Y.KeyMetadata.Arn
    Y.KeyMetadata.KeyManager != "CUSTOMER"
}

msk_data_is_encrypted_err = "Ensure AWS MSK data is encrypted using GS managed key." {
    not msk_data_is_encrypted
}

msk_data_is_encrypted_metadata := {
    "Policy Code": "PR-AWS-CLD-MSK-008",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS MSK data is encrypted using GS managed key.",
    "Policy Description": "It is to check that MSK data is enabled with data at rest encryption using firm-managed CMK only.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/kafka.html#Kafka.Client.describe_cluster",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/kms.html#KMS.Client.describe_key"
}