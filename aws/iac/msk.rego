package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-msk-cluster.html

#
# PR-AWS-CFR-MSK-001
#
default msk_encryption_at_rest_cmk = null

aws_issue["msk_encryption_at_rest_cmk"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::msk::cluster"
    not resource.Properties.EncryptionInfo.EncryptionAtRest.DataVolumeKMSKeyId
}

source_path[{"msk_encryption_at_rest_cmk": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::msk::cluster"
    not resource.Properties.EncryptionInfo.EncryptionAtRest.DataVolumeKMSKeyId
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "EncryptionInfo", "EncryptionAtRest", "DataVolumeKMSKeyId"]
        ],
    }
}

aws_issue["msk_encryption_at_rest_cmk"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::msk::cluster"
    count(resource.Properties.EncryptionInfo.EncryptionAtRest.DataVolumeKMSKeyId) == 0
}

source_path[{"msk_encryption_at_rest_cmk": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::msk::cluster"
    count(resource.Properties.EncryptionInfo.EncryptionAtRest.DataVolumeKMSKeyId) == 0
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "EncryptionInfo", "EncryptionAtRest", "DataVolumeKMSKeyId"]
        ],
    }
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
    "Policy Code": "PR-AWS-CFR-MSK-001",
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
# PR-AWS-CFR-MSK-002
#
default msk_in_transit_encryption = null

aws_bool_issue["msk_in_transit_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::msk::cluster"
    not resource.Properties.EncryptionInfo.EncryptionInTransit.InCluster
}

source_path[{"msk_in_transit_encryption": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::msk::cluster"
    not resource.Properties.EncryptionInfo.EncryptionInTransit.InCluster
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "EncryptionInfo", "EncryptionInTransit", "InCluster"]
        ],
    }
}

aws_issue["msk_in_transit_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::msk::cluster"
    lower(resource.Properties.EncryptionInfo.EncryptionInTransit.InCluster) == "false"
}

source_path[{"msk_in_transit_encryption": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::msk::cluster"
    lower(resource.Properties.EncryptionInfo.EncryptionInTransit.InCluster) == "false"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "EncryptionInfo", "EncryptionInTransit", "InCluster"]
        ],
    }
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
    "Policy Code": "PR-AWS-CFR-MSK-002",
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
# PR-AWS-CFR-MSK-003
#
default msk_in_transit_encryption_tls = null

aws_bool_issue["msk_in_transit_encryption_tls"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::msk::cluster"
    not resource.Properties.EncryptionInfo.EncryptionInTransit.ClientBroker
}

source_path[{"msk_in_transit_encryption_tls": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::msk::cluster"
    not resource.Properties.EncryptionInfo.EncryptionInTransit.ClientBroker
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "EncryptionInfo", "EncryptionInTransit", "ClientBroker"]
        ],
    }
}

aws_issue["msk_in_transit_encryption_tls"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::msk::cluster"
    lower(resource.Properties.EncryptionInfo.EncryptionInTransit.ClientBroker) != "tls"
}

source_path[{"msk_in_transit_encryption_tls": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::msk::cluster"
    lower(resource.Properties.EncryptionInfo.EncryptionInTransit.ClientBroker) != "tls"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "EncryptionInfo", "EncryptionInTransit", "ClientBroker"]
        ],
    }
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
    "Policy Code": "PR-AWS-CFR-MSK-003",
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
# PR-AWS-CFR-MSK-004
#
default msk_vpc = null

aws_issue["msk_vpc"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::msk::cluster"
    not resource.Properties.BrokerNodeGroupInfo.ClientSubnets
}

source_path[{"msk_vpc": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::msk::cluster"
    not resource.Properties.BrokerNodeGroupInfo.ClientSubnets
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "BrokerNodeGroupInfo", "ClientSubnets"]
        ],
    }
}

aws_issue["msk_vpc"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::msk::cluster"
    count(resource.Properties.BrokerNodeGroupInfo.ClientSubnets) == 0
}

source_path[{"msk_vpc": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::msk::cluster"
    count(resource.Properties.BrokerNodeGroupInfo.ClientSubnets) == 0
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "BrokerNodeGroupInfo", "ClientSubnets"]
        ],
    }
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
    "Policy Code": "PR-AWS-CFR-MSK-004",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure MSK cluster is setup in GS VPC",
    "Policy Description": "To Add MKS Cluster in gs VPC,Specify exactly two subnets if you are using the US West (N. California) Region. For other Regions where Amazon MSK is available, you can specify either two or three subnets. The subnets that you specify must be in distinct Availability Zones. When you create a cluster, Amazon MSK distributes the broker nodes evenly across the subnets that you specify.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-msk-cluster.html#cfn-msk-cluster-encryptioninfo"
}

#
# PR-AWS-CFR-MSK-005
#
default msk_cluster_logging_enable = null

aws_issue["msk_cluster_logging_enable"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::msk::cluster"
    not resource.Properties.LoggingInfo.BrokerLogs
}

source_path[{"msk_cluster_logging_enable": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::msk::cluster"
    not resource.Properties.LoggingInfo.BrokerLogs
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "LoggingInfo", "BrokerLogs"]
        ],
    }
}

msk_cluster_logging_enable {
    lower(input.Resources[i].Type) == "aws::msk::cluster"
    not aws_issue["msk_cluster_logging_enable"]
}

msk_cluster_logging_enable = false {
    aws_issue["msk_cluster_logging_enable"]
}

msk_cluster_logging_enable_err = "Ensure Amazon MSK cluster has logging enabled" {
    aws_issue["msk_cluster_logging_enable"]
}


msk_cluster_logging_enable_metadata := {
    "Policy Code": "PR-AWS-CFR-MSK-005",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure Amazon MSK cluster has logging enabled",
    "Policy Description": "Consistent cluster logging helps you determine if a request was made with root or AWS Identity and Access Management (IAM) user credentials and whether the request was made with temporary security credentials for a role or federated user.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-brokerlogs.html#cfn-msk-cluster-brokerlogs-cloudwatchlogs"
}


#
# PR-AWS-CFR-MSK-006
#

default msk_cluster_enhanced_monitoring_enable = null

aws_issue["msk_cluster_enhanced_monitoring_enable"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::msk::cluster"
    not resource.Properties.EnhancedMonitoring
}

aws_issue["msk_cluster_enhanced_monitoring_enable"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::msk::cluster"
    resource.Properties.EnhancedMonitoring == ""
}

aws_issue["msk_cluster_enhanced_monitoring_enable"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::msk::cluster"
    resource.Properties.EnhancedMonitoring == null
}

aws_issue["msk_cluster_enhanced_monitoring_enable"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::msk::cluster"
    lower(resource.Properties.EnhancedMonitoring) == "default"
}

msk_cluster_enhanced_monitoring_enable {
    lower(input.Resources[i].Type) == "aws::msk::cluster"
    not aws_issue["msk_cluster_enhanced_monitoring_enable"]
}

msk_cluster_enhanced_monitoring_enable = false {
    aws_issue["msk_cluster_enhanced_monitoring_enable"]
}

msk_cluster_enhanced_monitoring_enable_err = "Ensure enhanaced monitoring for AWS MSK is not set to default." {
    aws_issue["msk_cluster_enhanced_monitoring_enable"]
}


msk_cluster_enhanced_monitoring_enable_metadata := {
    "Policy Code": "PR-AWS-CFR-MSK-006",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure enhanaced monitoring for AWS MSK is not set to default.",
    "Policy Description": "It is used to check that enhanced monitoring is configured to gather Apache Kafka metrics and sends them to Amazon CloudWatch.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-msk-cluster.html#aws-resource-msk-cluster--examples"
}


#
# PR-AWS-CFR-MSK-007
#

default msk_public_access = null

aws_issue["msk_public_access"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::msk::cluster"
    lower(resource.Properties.BrokerNodeGroupInfo.ConnectivityInfo.PublicAccess.Type) != "disabled"
}

msk_public_access {
    lower(input.Resources[i].Type) == "aws::msk::cluster"
    not aws_issue["msk_public_access"]
}

msk_public_access = false {
    aws_issue["msk_public_access"]
}

msk_public_access_err = "Ensure public access is disabled for AWS MSK." {
    aws_issue["msk_public_access"]
}


msk_public_access_metadata := {
    "Policy Code": "PR-AWS-CFR-MSK-007",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure public access is disabled for AWS MSK.",
    "Policy Description": "It check whether public access is turned on to the brokers of MSK clusters.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-msk-cluster.html#aws-resource-msk-cluster--examples"
}