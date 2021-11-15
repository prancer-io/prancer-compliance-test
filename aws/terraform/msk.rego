package rule


#
# PR-AWS-TRF-MSK-001
#
default msk_encryption_at_rest_cmk = null

aws_attribute_absence["msk_encryption_at_rest_cmk"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_msk_cluster"
    not resource.properties.encryption_info
}

source_path[{"msk_encryption_at_rest_cmk": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_msk_cluster"
    not resource.properties.encryption_info

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "encryption_info"]
        ],
    }
}

aws_issue["msk_encryption_at_rest_cmk"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_msk_cluster"
    encryption_info := resource.properties.encryption_info[j]
    not encryption_info.encryption_at_rest_kms_key_arn
}

source_path[{"msk_encryption_at_rest_cmk": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_msk_cluster"
    encryption_info := resource.properties.encryption_info[j]
    not encryption_info.encryption_at_rest_kms_key_arn

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "encryption_info", j, "encryption_at_rest_kms_key_arn"]
        ],
    }
}

aws_issue["msk_encryption_at_rest_cmk"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_msk_cluster"
    encryption_info := resource.properties.encryption_info[j]
    count(encryption_info.encryption_at_rest_kms_key_arn) == 0
}

source_path[{"msk_encryption_at_rest_cmk": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_msk_cluster"
    encryption_info := resource.properties.encryption_info[j]
    count(encryption_info.encryption_at_rest_kms_key_arn) == 0

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "encryption_info", j, "encryption_at_rest_kms_key_arn"]
        ],
    }
}

aws_issue["msk_encryption_at_rest_cmk"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_msk_cluster"
    encryption_info := resource.properties.encryption_info[j]
    encryption_info.encryption_at_rest_kms_key_arn == null
}

source_path[{"msk_encryption_at_rest_cmk": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_msk_cluster"
    encryption_info := resource.properties.encryption_info[j]
    encryption_info.encryption_at_rest_kms_key_arn == null

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "encryption_info", j, "encryption_at_rest_kms_key_arn"]
        ],
    }
}

msk_encryption_at_rest_cmk {
    lower(input.resources[i].type) == "aws_msk_cluster"
    not aws_issue["msk_encryption_at_rest_cmk"]
    not aws_attribute_absence["msk_encryption_at_rest_cmk"]
}

msk_encryption_at_rest_cmk = false {
    aws_issue["msk_encryption_at_rest_cmk"]
}

msk_encryption_at_rest_cmk = false {
    aws_attribute_absence["msk_encryption_at_rest_cmk"]
}

msk_encryption_at_rest_cmk_err = "Use KMS Customer Master Keys for AWS MSK Clusters" {
    aws_issue["msk_encryption_at_rest_cmk"]
} else = "Use KMS Customer Master Keys for AWS MSK Clusters" {
    aws_attribute_absence["msk_encryption_at_rest_cmk"]
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

aws_attribute_absence["msk_in_transit_encryption"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_msk_cluster"
    not resource.properties.encryption_info
}

source_path[{"msk_in_transit_encryption": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_msk_cluster"
    not resource.properties.encryption_info

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "encryption_info"]
        ],
    }
}

aws_bool_issue["msk_in_transit_encryption"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_msk_cluster"
    encryption_info := resource.properties.encryption_info[j]
    encryption_in_transit := encryption_info.encryption_in_transit[k]
    not encryption_in_transit.in_cluster
}

source_path[{"msk_in_transit_encryption": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_msk_cluster"
    encryption_info := resource.properties.encryption_info[j]
    encryption_in_transit := encryption_info.encryption_in_transit[k]
    not encryption_in_transit.in_cluster

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "encryption_info", j, "encryption_in_transit", k, "in_cluster"]
        ],
    }
}

aws_issue["msk_in_transit_encryption"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_msk_cluster"
    encryption_info := resource.properties.encryption_info[j]
    encryption_in_transit := encryption_info.encryption_in_transit[k]
    lower(encryption_in_transit.in_cluster) == "false"
}

source_path[{"msk_in_transit_encryption": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_msk_cluster"
    encryption_info := resource.properties.encryption_info[j]
    encryption_in_transit := encryption_info.encryption_in_transit[k]
    lower(encryption_in_transit.in_cluster) == "false"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "encryption_info", j, "encryption_in_transit", k, "in_cluster"]
        ],
    }
}

msk_in_transit_encryption {
    lower(input.resources[i].type) == "aws_msk_cluster"
    not aws_issue["msk_in_transit_encryption"]
    not aws_attribute_absence["msk_in_transit_encryption"]
    not aws_bool_issue["msk_in_transit_encryption"]
}

msk_in_transit_encryption = false {
    aws_issue["msk_in_transit_encryption"]
}

msk_in_transit_encryption = false {
    aws_attribute_absence["msk_in_transit_encryption"]
}

msk_in_transit_encryption = false {
    aws_bool_issue["msk_in_transit_encryption"]
}


msk_in_transit_encryption_err = "Ensure data is Encrypted in transit (TLS)" {
    aws_issue["msk_in_transit_encryption"]
} else = "Ensure data is Encrypted in transit (TLS)" {
    aws_bool_issue["msk_in_transit_encryption"]
} else = "Ensure data is Encrypted in transit (TLS)" {
    aws_attribute_absence["msk_in_transit_encryption"]
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

aws_attribute_absence["msk_in_transit_encryption_tls"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_msk_cluster"
    not resource.properties.encryption_info
}

source_path[{"msk_in_transit_encryption_tls": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_msk_cluster"
    not resource.properties.encryption_info

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "encryption_info"]
        ],
    }
}

aws_bool_issue["msk_in_transit_encryption_tls"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_msk_cluster"
    encryption_info := resource.properties.encryption_info[j]
    encryption_in_transit := encryption_info.encryption_in_transit[k]
    not encryption_in_transit.client_broker
}

source_path[{"msk_in_transit_encryption_tls": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_msk_cluster"
    encryption_info := resource.properties.encryption_info[j]
    encryption_in_transit := encryption_info.encryption_in_transit[k]
    not encryption_in_transit.client_broker

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "encryption_info", j, "encryption_in_transit", k, "client_broker"]
        ],
    }
}

aws_issue["msk_in_transit_encryption_tls"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_msk_cluster"
    encryption_info := resource.properties.encryption_info[j]
    encryption_in_transit := encryption_info.encryption_in_transit[k]
    lower(encryption_in_transit.client_broker) != "tls"
}

source_path[{"msk_in_transit_encryption_tls": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_msk_cluster"
    encryption_info := resource.properties.encryption_info[j]
    encryption_in_transit := encryption_info.encryption_in_transit[k]
    lower(encryption_in_transit.client_broker) != "tls"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "encryption_info", j, "encryption_in_transit", k, "client_broker"]
        ],
    }
}

msk_in_transit_encryption_tls {
    lower(input.resources[i].type) == "aws_msk_cluster"
    not aws_issue["msk_in_transit_encryption_tls"]
    not aws_bool_issue["msk_in_transit_encryption_tls"]
    not aws_attribute_absence["msk_in_transit_encryption_tls"]
}

msk_in_transit_encryption_tls = false {
    aws_issue["msk_in_transit_encryption_tls"]
}

msk_in_transit_encryption_tls = false {
    aws_attribute_absence["msk_in_transit_encryption_tls"]
}

msk_in_transit_encryption_tls = false {
    aws_bool_issue["msk_in_transit_encryption_tls"]
}

msk_in_transit_encryption_tls_err = "Ensure client authentication is enabled with TLS (mutual TLS authentication)" {
    aws_issue["msk_in_transit_encryption_tls"]
} else = "Ensure client authentication is enabled with TLS (mutual TLS authentication)" {
    aws_bool_issue["msk_in_transit_encryption_tls"]
} else = "Ensure client authentication is enabled with TLS (mutual TLS authentication)" {
    aws_attribute_absence["msk_in_transit_encryption_tls"]
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
    broker_node_group_info := resource.properties.broker_node_group_info[j]
    not broker_node_group_info.client_subnets
}

source_path[{"msk_vpc": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_msk_cluster"
    broker_node_group_info := resource.properties.broker_node_group_info[j]
    not broker_node_group_info.client_subnets

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "broker_node_group_info", j, "client_subnets"]
        ],
    }
}

aws_issue["msk_vpc"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_msk_cluster"
    broker_node_group_info := resource.properties.broker_node_group_info[j]
    count(broker_node_group_info.client_subnets) == 0
}

source_path[{"msk_vpc": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_msk_cluster"
    broker_node_group_info := resource.properties.broker_node_group_info[j]
    count(broker_node_group_info.client_subnets) == 0

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "broker_node_group_info", j, "client_subnets"]
        ],
    }
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


#
# PR-AWS-TRF-MSK-005
#

default msk_cluster_logging_enable = null

aws_issue["msk_cluster_logging_enable"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_msk_cluster"
    logging_info := resource.properties.logging_info[j]
    not logging_info.broker_logs
}

source_path[{"msk_cluster_logging_enable": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_msk_cluster"
    logging_info := resource.properties.logging_info[j]
    not logging_info.broker_logs
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "logging_info", "broker_logs"]
        ],
    }
}

aws_issue["msk_cluster_logging_enable"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_msk_cluster"
    logging_info := resource.properties.logging_info[j]
    count(logging_info.broker_logs) == 0
}

source_path[{"msk_cluster_logging_enable": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_msk_cluster"
    logging_info := resource.properties.logging_info[j]
    count(logging_info.broker_logs) == 0
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "logging_info", "broker_logs"]
        ],
    }
}

aws_issue["msk_cluster_logging_enable"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_msk_cluster"
    count(resource.properties.logging_info) == 0
}

source_path[{"msk_cluster_logging_enable": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_msk_cluster"
    count(resource.properties.logging_info) == 0
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "logging_info", "broker_logs"]
        ],
    }
}

msk_cluster_logging_enable {
    lower(input.resources[i].type) == "aws_msk_cluster"
    not aws_issue["msk_cluster_logging_enable"]
}

msk_cluster_logging_enable = false {
    aws_issue["msk_cluster_logging_enable"]
}

msk_cluster_logging_enable_err = "Ensure Amazon MSK cluster has logging enabled" {
    aws_issue["msk_cluster_logging_enable"]
}


msk_cluster_logging_enable_metadata := {
    "Policy Code": "PR-AWS-TRF-MSK-005",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure Amazon MSK cluster has logging enabled",
    "Policy Description": "Consistent cluster logging helps you determine if a request was made with root or AWS Identity and Access Management (IAM) user credentials and whether the request was made with temporary security credentials for a role or federated user.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/msk_cluster"
}