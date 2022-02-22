package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-cluster.html

#
# PR-AWS-CFR-EKS-001
#

default eks_multiple_sg = null

aws_issue["eks_multiple_sg"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::eks::cluster"
    not resource.Properties.ResourcesVpcConfig.SecurityGroupIds
}

source_path[{"eks_multiple_sg": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::eks::cluster"
    not resource.Properties.ResourcesVpcConfig.SecurityGroupIds
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "ResourcesVpcConfig", "SecurityGroupIds"]
        ],
    }
}

aws_issue["eks_multiple_sg"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::eks::cluster"
    count(resource.Properties.ResourcesVpcConfig.SecurityGroupIds) > 1
}

source_path[{"eks_multiple_sg": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::eks::cluster"
    count(resource.Properties.ResourcesVpcConfig.SecurityGroupIds) > 1
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "ResourcesVpcConfig", "SecurityGroupIds"]
        ],
    }
}

eks_multiple_sg {
    lower(input.Resources[i].Type) == "aws::eks::cluster"
    not aws_issue["eks_multiple_sg"]
}

eks_multiple_sg = false {
    aws_issue["eks_multiple_sg"]
}

eks_multiple_sg_err = "AWS EKS cluster control plane assigned multiple security groups" {
    aws_issue["eks_multiple_sg"]
}

eks_multiple_sg_metadata := {
    "Policy Code": "PR-AWS-CFR-EKS-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS EKS cluster control plane assigned multiple security groups",
    "Policy Description": "Amazon EKS strongly recommends that you use a dedicated security group for each cluster control plane (one per cluster). This policy checks the number of security groups assigned to your cluster's control plane and alerts if there are more than one.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-cluster.html"
}

#
# PR-AWS-CFR-EKS-002
#

default eks_version = null

aws_issue["eks_version"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::eks::cluster"
    startswith(lower(resource.Properties.Version), "1.9.")
}

source_path[{"eks_version": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::eks::cluster"
    startswith(lower(resource.Properties.Version), "1.9.")
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "Version"]
        ],
    }
}

eks_version {
    lower(input.Resources[i].Type) == "aws::eks::cluster"
    not aws_issue["eks_version"]
}

eks_version = false {
    aws_issue["eks_version"]
}

eks_version_err = "AWS EKS unsupported Master node version." {
    aws_issue["eks_version"]
}
eks_version_metadata := {
    "Policy Code": "PR-AWS-CFR-EKS-002",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS EKS unsupported Master node version.",
    "Policy Description": "Ensure your EKS Master node version is supported. This policy checks your EKS master node version and generates an alert if the version running is unsupported.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-cluster.html#cfn-eks-cluster-version"
}


#
# PR-AWS-CFR-EKS-003
#

default eks_encryption_resources = null

aws_attribute_absence["eks_encryption_resources"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::eks::cluster"
    not resource.Properties.EncryptionConfig
}

source_path[{"eks_encryption_resources": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::eks::cluster"
    not resource.Properties.EncryptionConfig
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "EncryptionConfig"]
        ],
    }
}

aws_issue["eks_encryption_resources"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::eks::cluster"
    EncryptionConfig := resource.Properties.EncryptionConfig[j]
    not EncryptionConfig.Resources
}

source_path[{"eks_encryption_resources": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::eks::cluster"
    EncryptionConfig := resource.Properties.EncryptionConfig[j]
    not EncryptionConfig.Resources
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "EncryptionConfig", j, "Resources"]
        ],
    }
}

aws_issue["eks_encryption_resources"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::eks::cluster"
    EncryptionConfig := resource.Properties.EncryptionConfig[j]
    count(EncryptionConfig.Resources) == 0
}

source_path[{"eks_encryption_resources": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::eks::cluster"
    EncryptionConfig := resource.Properties.EncryptionConfig[j]
    count(EncryptionConfig.Resources) == 0
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "EncryptionConfig", j, "Resources"]
        ],
    }
}

eks_encryption_resources {
    lower(input.Resources[i].Type) == "aws::eks::cluster"
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
    "Policy Code": "PR-AWS-CFR-EKS-003",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure AWS EKS cluster has secrets encryption enabled",
    "Policy Description": "Secrets in Kubernetes enables managing sensitive information such as passwords and API keys using Kubernetes-native APIs. When creating a secret resource the Kubernetes API server stores it in etcd in a base64 encoded form.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-eks-cluster-encryptionconfig.html#cfn-eks-cluster-encryptionconfig-resources"
}


#
# PR-AWS-CFR-EKS-004
#

default eks_encryption_kms = null

aws_attribute_absence["eks_encryption_kms"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::eks::cluster"
    not resource.Properties.EncryptionConfig
}

source_path[{"eks_encryption_kms": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::eks::cluster"
    not resource.Properties.EncryptionConfig
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "EncryptionConfig"]
        ],
    }
}

aws_issue["eks_encryption_kms"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::eks::cluster"
    EncryptionConfig := resource.Properties.EncryptionConfig[j]
    not EncryptionConfig.Provider.keyArn
}

source_path[{"eks_encryption_resources": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::eks::cluster"
    EncryptionConfig := resource.Properties.EncryptionConfig[j]
    not EncryptionConfig.Provider.keyArn
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "EncryptionConfig", j, "Provider", "keyArn"]
        ],
    }
}

aws_issue["eks_encryption_kms"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::eks::cluster"
    EncryptionConfig := resource.Properties.EncryptionConfig[j]
    count(EncryptionConfig.Provider.keyArn) == 0
}

source_path[{"eks_encryption_resources": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::eks::cluster"
    EncryptionConfig := resource.Properties.EncryptionConfig[j]
    count(EncryptionConfig.Provider.keyArn) == 0
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "EncryptionConfig", j, "Provider", "keyArn"]
        ],
    }
}

eks_encryption_kms {
    lower(input.Resources[i].Type) == "aws::eks::cluster"
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
    "Policy Code": "PR-AWS-CFR-EKS-004",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure Kubernetes secrets are encrypted using CMKs managed in AWS KMS",
    "Policy Description": "Application-layer Secrets Encryption provides an additional layer of security for sensitive data, such as user defined Secrets and Secrets required for the operation of the cluster, such as service account keys, which are all stored in etcd. Using this functionality, you can use a key, that you manage in AWS KMS, to encrypt data at the application layer",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-eks-cluster-encryptionconfig.html#cfn-eks-cluster-encryptionconfig-provider"
}


#
# PR-AWS-CFR-EKS-005
#

default eks_pblic_endpoint = null

aws_issue["eks_pblic_endpoint"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::eks::cluster"
    resource.Properties.ResourcesVpcConfig.EndpointPrivateAccess == false
}

aws_issue["eks_pblic_endpoint"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::eks::cluster"
    resource.Properties.ResourcesVpcConfig.EndpointPublicAccess == true
}

eks_pblic_endpoint {
    lower(input.Resources[i].Type) == "aws::eks::cluster"
    not aws_issue["eks_pblic_endpoint"]
}

eks_pblic_endpoint = false {
    aws_issue["eks_pblic_endpoint"]
}

eks_pblic_endpoint_err = "Ensure communication to and from EKS remains private." {
    aws_issue["eks_pblic_endpoint"]
}

eks_pblic_endpoint_metadata := {
    "Policy Code": "PR-AWS-CFR-EKS-005",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure communication to and from EKS remains private.",
    "Policy Description": "Ensure communication to and from EKS remains private.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-eks-cluster-encryptionconfig.html#cfn-eks-cluster-encryptionconfig-provider"
}
