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

aws_attribute_absence["eks_encryption_resources"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_eks_cluster"
    not resource.properties.encryption_config
}

source_path[{"eks_encryption_resources": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_eks_cluster"
    not resource.properties.encryption_config
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "encryption_config"]
        ],
    }
}

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
    not aws_attribute_absence["eks_encryption_resources"]
}

eks_encryption_resources = false {
    aws_issue["eks_encryption_resources"]
}

eks_encryption_resources = false {
    aws_attribute_absence["eks_encryption_resources"]
}

eks_encryption_resources_err = "Ensure AWS EKS cluster has secrets encryption enabled" {
    aws_issue["eks_encryption_resources"]
} else = "Ensure AWS EKS cluster has secrets encryption enabled" {
    aws_attribute_absence["eks_encryption_resources"]
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

aws_attribute_absence["eks_encryption_kms"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_eks_cluster"
    not resource.properties.encryption_config

}

source_path[{"eks_encryption_resources": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_eks_cluster"
    not resource.properties.encryption_config
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "encryption_config"]
        ],
    }
}

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
    not aws_attribute_absence["eks_encryption_kms"]
}

eks_encryption_kms = false {
    aws_issue["eks_encryption_kms"]
}

eks_encryption_kms = false {
    aws_attribute_absence["eks_encryption_kms"]
}

eks_encryption_kms_err = "Ensure Kubernetes secrets are encrypted using CMKs managed in AWS KMS" {
    aws_issue["eks_encryption_kms"]
} else = "Ensure Kubernetes secrets are encrypted using CMKs managed in AWS KMS" {
    aws_attribute_absence["eks_encryption_kms"]
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


#
# PR-AWS-TRF-EKS-006
#

default eks_approved_kubernetes_version = null

kubernetes_platform_version := ["1.20", "1.19", "1.18"]

aws_issue["eks_approved_kubernetes_version"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_eks_cluster"
    count([c | resource.properties.version == kubernetes_platform_version[_]; c:=1]) != 0
}

eks_approved_kubernetes_version = false {
    aws_issue["eks_approved_kubernetes_version"]
}

eks_approved_kubernetes_version {
    lower(input.resources[i].type) == "aws_eks_cluster"
    not aws_issue["eks_approved_kubernetes_version"]
}

eks_approved_kubernetes_version_err = "Ensure AWS EKS only uses latest versions of Kubernetes." {
    aws_issue["eks_approved_kubernetes_version"]
}

eks_approved_kubernetes_version_metadata := {
    "Policy Code": "PR-AWS-TRF-EKS-006",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure AWS EKS only uses latest versions of Kubernetes.",
    "Policy Description": "It checks if an approved version of Kubernetes is used for EKS cluster or not.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eks_cluster"
}


#
# PR-AWS-TRF-EKS-007
#

default eks_with_security_group_attached = null

aws_issue["eks_with_security_group_attached"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_eks_cluster"
    vpc_config := resource.properties.vpc_config[j]
    not vpc_config.security_group_ids
}

eks_with_security_group_attached = false {
    aws_issue["eks_with_security_group_attached"]
}

eks_with_security_group_attached {
    lower(input.resources[i].type) == "aws_eks_cluster"
    not aws_issue["eks_with_security_group_attached"]
}

eks_with_security_group_attached_err = "Ensure EKS cluster is configured with control plane security group attached to it." {
    aws_issue["eks_with_security_group_attached"]
}

eks_with_security_group_attached_metadata := {
    "Policy Code": "PR-AWS-TRF-EKS-007",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure EKS cluster is configured with control plane security group attached to it.",
    "Policy Description": "It checks if the cluster node security groups is configured or not.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eks_cluster"
}


#
# PR-AWS-TRF-EKS-008
#

default eks_with_private_access = null

aws_issue["eks_with_private_access"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_eks_cluster"
    vpc_config := resource.properties.vpc_config[j]
    not vpc_config.endpoint_private_access
}

eks_with_private_access = false {
    aws_issue["eks_with_private_access"]
}

eks_with_private_access {
    lower(input.resources[i].type) == "aws_eks_cluster"
    not aws_issue["eks_with_private_access"]
}

eks_with_private_access_err = "Ensure only private access for Amazon EKS cluster's Kubernetes API is enabled." {
    aws_issue["eks_with_private_access"]
}

eks_with_private_access_metadata := {
    "Policy Code": "PR-AWS-TRF-EKS-008",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure only private access for Amazon EKS cluster's Kubernetes API is enabled.",
    "Policy Description": "This policy checks if the EKS cluster has public access which can be accessed over the internet.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eks_cluster"
}


#
# PR-AWS-TRF-EKS-009
#

default eks_logging_enabled = null

aws_issue["eks_logging_enabled"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_eks_cluster"
    not resource.properties.enabled_cluster_log_types
}

aws_issue["eks_logging_enabled"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_eks_cluster"
    count(resource.properties.enabled_cluster_log_types) == 0
}

eks_logging_enabled = false {
    aws_issue["eks_logging_enabled"]
}

eks_logging_enabled {
    lower(input.resources[i].type) == "aws_eks_cluster"
    not aws_issue["eks_logging_enabled"]
}

eks_logging_enabled_err = "Ensure AWS EKS control plane logging is enabled." {
    aws_issue["eks_logging_enabled"]
}

eks_logging_enabled_metadata := {
    "Policy Code": "PR-AWS-TRF-EKS-009",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure AWS EKS control plane logging is enabled.",
    "Policy Description": "Amazon EKS control plane logging provides audit and diagnostic logs directly from the Amazon EKS control plane to CloudWatch Logs in your account. These logs make it easy for you to secure and run your clusters. You can select the exact log types you need, and logs are sent as log streams to a group for each Amazon EKS cluster in CloudWatch. This policy generates an alert if control plane logging is disabled.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eks_cluster"
}