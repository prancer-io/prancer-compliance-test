package rule


#
# PR-AWS-TRF-MSK-001
#
default msk_encryption_at_rest_cmk = null

aws_issue["msk_encryption_at_rest_cmk"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_msk_cluster"
    encryption_info := resource.properties.encryption_info[_]
    not encryption_info.encryption_at_rest_kms_key_arn
}

aws_issue["msk_encryption_at_rest_cmk"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_msk_cluster"
    encryption_info := resource.properties.encryption_info[_]
    count(encryption_info.encryption_at_rest_kms_key_arn) == 0
}

aws_issue["msk_encryption_at_rest_cmk"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_msk_cluster"
    encryption_info := resource.properties.encryption_info[_]
    encryption_info.encryption_at_rest_kms_key_arn == null
}

msk_encryption_at_rest_cmk {
    lower(input.resources[i].type) == "aws_msk_cluster"
    not aws_issue["msk_encryption_at_rest_cmk"]
}

msk_encryption_at_rest_cmk = false {
    aws_issue["msk_encryption_at_rest_cmk"]
}

msk_encryption_at_rest_cmk_err = "Use KMS Customer Master Keys for AWS MSK Clusters" {
    aws_issue["msk_encryption_at_rest_cmk"]
}


msk_encryption_at_rest_cmk_metadata := {
    "Policy Code": "PR-AWS-TRF-MSK-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Use KMS Customer Master Keys for AWS MSK Clusters",
    "Policy Description": "Ensure that Amazon Managed Streaming for Kafka (MSK) clusters are using AWS KMS Customer Master Keys (CMKs) instead of AWS managed-keys (i.e. default keys) for data encryption, in order to have a fine-grained control over data-at-rest encryption/decryption process and meet compliance requirements. MSK is a fully managed AWS service that enables you to migrate, build and run real-time streaming applications on Apache Kafka.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-msk-cluster.html#cfn-msk-cluster-encryptioninfo"
}

#
# PR-AWS-TRF-MSK-002
#
default msk_in_transit_encryption = null

aws_bool_issue["msk_in_transit_encryption"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_msk_cluster"
    encryption_info := resource.properties.encryption_info[_]
    encryption_in_transit := encryption_info.encryption_in_transit[_]
    not encryption_in_transit.in_cluster
}

aws_issue["msk_in_transit_encryption"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_msk_cluster"
    encryption_info := resource.properties.encryption_info[_]
    encryption_in_transit := encryption_info.encryption_in_transit[_]
    lower(encryption_in_transit.in_cluster) == "false"
}

msk_in_transit_encryption {
    lower(input.resources[i].type) == "aws_msk_cluster"
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
    "Policy Code": "PR-AWS-TRF-MSK-002",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure data is Encrypted in transit (TLS)",
    "Policy Description": "Ensure data is Encrypted in transit (TLS)",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-msk-cluster.html#cfn-msk-cluster-encryptioninfo"
}

#
# PR-AWS-TRF-MSK-003
#
default msk_in_transit_encryption_tls = null

aws_bool_issue["msk_in_transit_encryption_tls"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_msk_cluster"
    encryption_info := resource.properties.encryption_info[_]
    encryption_in_transit := encryption_info.encryption_in_transit[_]
    not encryption_in_transit.client_broker
}

aws_issue["msk_in_transit_encryption_tls"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_msk_cluster"
    encryption_info := resource.properties.encryption_info[_]
    encryption_in_transit := encryption_info.encryption_in_transit[_]
    lower(encryption_in_transit.client_broker) != "tls"
}

msk_in_transit_encryption_tls {
    lower(input.resources[i].type) == "aws_msk_cluster"
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
    "Policy Code": "PR-AWS-TRF-MSK-003",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure client authentication is enabled with TLS (mutual TLS authentication)",
    "Policy Description": "Enable TLS by setting EncryptionInfo.EncryptionInTransit.ClientBroker value to 'TLS'. to provide trasport layes security to MSK instance",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-msk-cluster.html#cfn-msk-cluster-encryptioninfo"
}

#
# PR-AWS-TRF-MSK-004
#
default msk_vpc = null

aws_issue["msk_vpc"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_msk_cluster"
    broker_node_group_info := resource.properties.broker_node_group_info[_]
    not broker_node_group_info.client_subnets
}

aws_issue["msk_vpc"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_msk_cluster"
    broker_node_group_info := resource.properties.broker_node_group_info[_]
    count(broker_node_group_info.client_subnets) == 0
}

msk_vpc {
    lower(input.resources[i].type) == "aws_msk_cluster"
    not aws_issue["msk_vpc"]
}

msk_vpc = false {
    aws_issue["msk_vpc"]
}


msk_vpc_err = "Ensure MSK cluster is setup in GS VPC" {
    aws_issue["msk_vpc"]
}


msk_vpc_metadata := {
    "Policy Code": "PR-AWS-TRF-MSK-004",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure MSK cluster is setup in GS VPC",
    "Policy Description": "To Add MKS Cluster in gs VPC,Specify exactly two subnets if you are using the US West (N. California) Region. For other Regions where Amazon MSK is available, you can specify either two or three subnets. The subnets that you specify must be in distinct Availability Zones. When you create a cluster, Amazon MSK distributes the broker nodes evenly across the subnets that you specify.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-msk-cluster.html#cfn-msk-cluster-encryptioninfo"
}