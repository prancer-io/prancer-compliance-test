package rule


#
# PR-AWS-TRF-EKS-001
#

default eks_multiple_sg = null

aws_attribute_absence["eks_multiple_sg"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_eks_cluster"
    not resource.properties.vpc_config
}

source_path[{"eks_multiple_sg": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_eks_cluster"
    not resource.properties.vpc_config

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "vpc_config"]
        ],
    }
}

aws_attribute_absence["eks_multiple_sg"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_eks_cluster"
    vpc_config := resource.properties.vpc_config[j]
    not vpc_config.security_group_ids
}

source_path[{"eks_multiple_sg": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_eks_cluster"
    vpc_config := resource.properties.vpc_config[j]
    not vpc_config.security_group_ids

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "vpc_config", j, "security_group_ids"]
        ],
    }
}

aws_issue["eks_multiple_sg"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_eks_cluster"
    vpc_config := resource.properties.vpc_config[j]
    count(vpc_config.security_group_ids) != 1
}

source_path[{"eks_multiple_sg": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_eks_cluster"
    vpc_config := resource.properties.vpc_config[j]
    count(vpc_config.security_group_ids) != 1

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "vpc_config", j, "security_group_ids"]
        ],
    }
}

eks_multiple_sg {
    lower(input.resources[i].type) == "aws_eks_cluster"
    not aws_issue["eks_multiple_sg"]
    not aws_attribute_absence["eks_multiple_sg"]
}

eks_multiple_sg = false {
    aws_issue["eks_multiple_sg"]
}

eks_multiple_sg = false {
    aws_attribute_absence["eks_multiple_sg"]
}

eks_multiple_sg_err = "AWS EKS cluster control plane assigned multiple security groups" {
    aws_issue["eks_multiple_sg"]
} else = "EKS cluster attribute security_group_ids missing in the resource" {
    aws_attribute_absence["eks_multiple_sg"]
}

eks_multiple_sg_metadata := {
    "Policy Code": "PR-AWS-TRF-EKS-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS EKS cluster control plane assigned multiple security groups",
    "Policy Description": "Amazon EKS strongly recommends that you use a dedicated security group for each cluster control plane (one per cluster). This policy checks the number of security groups assigned to your cluster's control plane and alerts if there are more than one.",
    "Resource Type": "aws_eks_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-cluster.html"
}

#
# PR-AWS-TRF-EKS-002
#

default eks_version = null

aws_issue["eks_version"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_eks_cluster"
    startswith(lower(resource.properties.version), "1.9.")
}

source_path[{"eks_version": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_eks_cluster"
    startswith(lower(resource.properties.version), "1.9.")

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "version"]
        ],
    }
}

eks_version {
    lower(input.resources[i].type) == "aws_eks_cluster"
    not aws_issue["eks_version"]
}

eks_version = false {
    aws_issue["eks_version"]
}

eks_version_err = "AWS EKS unsupported Master node version." {
    aws_issue["eks_version"]
}
eks_version_metadata := {
    "Policy Code": "PR-AWS-TRF-EKS-002",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS EKS unsupported Master node version.",
    "Policy Description": "Ensure your EKS Master node version is supported. This policy checks your EKS master node version and generates an alert if the version running is unsupported.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-cluster.html#cfn-eks-cluster-version"
}


#
# PR-AWS-TRF-EKS-003
#

default eks_encryption_resources = null

aws_issue["eks_encryption_resources"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_eks_cluster"
    encryption_config := resource.properties.encryption_config[j]
    not encryption_config.resources
}

source_path[{"eks_encryption_resources": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_eks_cluster"
    encryption_config := resource.properties.encryption_config[j]
    not encryption_config.resources
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "encryption_config", j, "resources"]
        ],
    }
}

aws_issue["eks_encryption_resources"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_eks_cluster"
    encryption_config := resource.properties.encryption_config[j]
    count(encryption_config.resources) == 0
}

source_path[{"eks_encryption_resources": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_eks_cluster"
    encryption_config := resource.properties.encryption_config[j]
    count(encryption_config.resources) == 0
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "encryption_config", j, "resources"]
        ],
    }
}

eks_encryption_resources {
    lower(input.resources[i].type) == "aws_eks_cluster"
    not aws_issue["eks_encryption_resources"]
}

eks_encryption_resources = false {
    aws_issue["eks_encryption_resources"]
}

eks_encryption_resources_err = "Ensure AWS EKS cluster has secrets encryption enabled" {
    aws_issue["eks_encryption_resources"]
}
eks_encryption_resources_metadata := {
    "Policy Code": "PR-AWS-TRF-EKS-003",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure AWS EKS cluster has secrets encryption enabled",
    "Policy Description": "Secrets in Kubernetes enables managing sensitive information such as passwords and API keys using Kubernetes-native APIs. When creating a secret resource the Kubernetes API server stores it in etcd in a base64 encoded form.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eks_cluster"
}



#
# PR-AWS-TRF-EKS-004
#

default eks_encryption_kms = null

aws_issue["eks_encryption_kms"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_eks_cluster"
    encryption_config := resource.properties.encryption_config[j]
    provider := encryption_config.provider[k]
    not provider.key_arn
}

source_path[{"eks_encryption_resources": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_eks_cluster"
    encryption_config := resource.properties.encryption_config[j]
    provider := encryption_config.provider[k]
    not provider.key_arn
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "encryption_config", j, "Provider", k, "key_arn"]
        ],
    }
}

aws_issue["eks_encryption_kms"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_eks_cluster"
    encryption_config := resource.properties.encryption_config[j]
    provider := encryption_config.provider[k]
    count(provider.key_arn) == 0
}

source_path[{"eks_encryption_resources": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_eks_cluster"
    encryption_config := resource.properties.encryption_config[j]
    provider := encryption_config.provider[k]
    count(provider.key_arn) == 0
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "encryption_config", j, "Provider", k, "key_arn"]
        ],
    }
}

eks_encryption_kms {
    lower(input.resources[i].type) == "aws_eks_cluster"
    not aws_issue["eks_encryption_kms"]
}

eks_encryption_kms = false {
    aws_issue["eks_encryption_kms"]
}

eks_encryption_kms_err = "Ensure Kubernetes secrets are encrypted using CMKs managed in AWS KMS" {
    aws_issue["eks_encryption_kms"]
}
eks_encryption_kms_metadata := {
    "Policy Code": "PR-AWS-TRF-EKS-004",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure Kubernetes secrets are encrypted using CMKs managed in AWS KMS",
    "Policy Description": "Application-layer Secrets Encryption provides an additional layer of security for sensitive data, such as user defined Secrets and Secrets required for the operation of the cluster, such as service account keys, which are all stored in etcd. Using this functionality, you can use a key, that you manage in AWS KMS, to encrypt data at the application layer",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eks_cluster"
}
