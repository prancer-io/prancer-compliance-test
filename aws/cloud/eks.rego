package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-cluster.html

available_true_choices := ["true", true]
available_false_choices := ["false", false]

#
# PR-AWS-CLD-EKS-001
#

# describe_cluster

default eks_multiple_sg = false

eks_multiple_sg = true {
    # lower(resource.Type) == "aws::eks::cluster"
    count(input.cluster.resourcesVpcConfig.securityGroupIds) < 1
}

eks_multiple_sg_err = "AWS EKS cluster control plane assigned multiple security groups" {
    not eks_multiple_sg
}

eks_multiple_sg_metadata := {
    "Policy Code": "PR-AWS-CLD-EKS-001",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS EKS cluster control plane assigned multiple security groups",
    "Policy Description": "Amazon EKS strongly recommends that you use a dedicated security group for each cluster control plane (one per cluster). This policy checks the number of security groups assigned to your cluster's control plane and alerts if there are more than one.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-cluster.html"
}

#
# PR-AWS-CLD-EKS-003
#

# describe_cluster

default eks_encryption_resources = true

eks_encryption_resources = false {
    # lower(resource.Type) == "aws::eks::cluster"
    not input.cluster.encryptionConfig
}

eks_encryption_resources_err = "Ensure AWS EKS cluster has secrets encryption enabled" {
    not eks_encryption_resources
}

eks_encryption_resources_metadata := {
    "Policy Code": "PR-AWS-CLD-EKS-003",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS EKS cluster has secrets encryption enabled",
    "Policy Description": "Secrets in Kubernetes enables managing sensitive information such as passwords and API keys using Kubernetes-native APIs. When creating a secret resource the Kubernetes API server stores it in etcd in a base64 encoded form.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-eks-cluster-encryptionconfig.html#cfn-eks-cluster-encryptionconfig-resources"
}


#
# PR-AWS-CLD-EKS-004
#

default eks_encryption_kms = true

eks_encryption_kms = false {
    resource := input.Resources[i]
    # lower(resource.Type) == "aws::eks::cluster"
    encryptionConfig := input.cluster.encryptionConfig[j]
    count(encryptionConfig.provider.keyArn) == 0
}

eks_encryption_kms_err = "Ensure Kubernetes secrets are encrypted using CMKs managed in AWS KMS" {
    not eks_encryption_kms
}

eks_encryption_kms_metadata := {
    "Policy Code": "PR-AWS-CLD-EKS-004",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure Kubernetes secrets are encrypted using CMKs managed in AWS KMS",
    "Policy Description": "Application-layer Secrets Encryption provides an additional layer of security for sensitive data, such as user defined Secrets and Secrets required for the operation of the cluster, such as service account keys, which are all stored in etcd. Using this functionality, you can use a key, that you manage in AWS KMS, to encrypt data at the application layer",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-eks-cluster-encryptionconfig.html#cfn-eks-cluster-encryptionconfig-provider"
}

#
# PR-AWS-CLD-EKS-006
#

default eks_approved_kubernetes_version = true

platform_version := ["1.20", "1.19", "1.18"]

eks_approved_kubernetes_version = false {
    # lower(resource.Type) == "aws::eks::cluster"
    count([c | input.cluster.platformVersion == platform_version[_]; c:=1]) != 0
}

eks_approved_kubernetes_version_err = "Ensure AWS EKS only uses latest versions of Kubernetes." {
    not eks_approved_kubernetes_version
}

eks_approved_kubernetes_version_metadata := {
    "Policy Code": "PR-AWS-CLD-EKS-006",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS EKS only uses latest versions of Kubernetes.",
    "Policy Description": "It checks if an approved version of Kubernetes is used for EKS cluster or not.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/eks.html#EKS.Client.describe_cluster"
}

#
# PR-AWS-CLD-EKS-007
#

default eks_with_security_group_attached = true

eks_with_security_group_attached = false {
    # lower(resource.Type) == "aws::eks::cluster"
    not input.cluster.resourcesVpcConfig.securityGroupIds
}

eks_with_security_group_attached_err = "Ensure EKS cluster is configured with control plane security group attached to it." {
    not eks_with_security_group_attached
}

eks_with_security_group_attached_metadata := {
    "Policy Code": "PR-AWS-CLD-EKS-007",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure EKS cluster is configured with control plane security group attached to it.",
    "Policy Description": "It checks if the cluster node security groups is configured or not.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/eks.html#EKS.Client.describe_cluster"
}

#
# PR-AWS-CLD-EKS-008
#

default eks_with_private_access = true

eks_with_private_access = false {
    # lower(resource.Type) == "aws::eks::cluster"
    input.cluster.resourcesVpcConfig.endpointPrivateAccess == available_false_choices[_]
}

eks_with_private_access = false {
    # lower(resource.Type) == "aws::eks::cluster"
    input.cluster.resourcesVpcConfig.endpointPublicAccess == available_true_choices[_]
}

eks_with_private_access_err = "Ensure only private access for Amazon EKS cluster's Kubernetes API is enabled." {
    not eks_with_private_access
}

eks_with_private_access_metadata := {
    "Policy Code": "PR-AWS-CLD-EKS-008",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure only private access for Amazon EKS cluster's Kubernetes API is enabled.",
    "Policy Description": "This policy checks if the EKS cluster has public access which can be accessed over the internet.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/eks.html#EKS.Client.describe_cluster"
}

#
# PR-AWS-CLD-EKS-009
#

default eks_logging_enabled = true

eks_logging_enabled = false {
    # lower(resource.Type) == "aws::eks::cluster"
    cluster_logging := input.cluster.logging.clusterLogging[_]
    cluster_logging.types == null
}

eks_logging_enabled = false {
    # lower(resource.Type) == "aws::eks::cluster"
    cluster_logging := input.cluster.logging.clusterLogging[_]
    count(cluster_logging.types) == 0
}

eks_logging_enabled = false {
    # lower(resource.Type) == "aws::eks::cluster"
    cluster_logging := input.cluster.logging.clusterLogging[_]
    cluster_logging.types == ""
}

eks_logging_enabled = false {
    # lower(resource.Type) == "aws::eks::cluster"
    cluster_logging := input.cluster.logging.clusterLogging[_]
    not cluster_logging.types
}

eks_logging_enabled = false {
    # lower(resource.Type) == "aws::eks::cluster"
    cluster_logging := input.cluster.logging.clusterLogging[_]
    cluster_logging.enabled == available_false_choices[_]
}

eks_logging_enabled_err = "Ensure AWS EKS control plane logging is enabled." {
    not eks_logging_enabled
}

eks_logging_enabled_metadata := {
    "Policy Code": "PR-AWS-CLD-EKS-009",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS EKS control plane logging is enabled.",
    "Policy Description": "This policy checks if the EKS cluster has public access which can be accessed over the internet.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/eks.html#EKS.Client.describe_cluster"
}


#
# PR-AWS-CLD-EKS-010
# aws::eks::cluster
# AWS::KMS::Key

default eks_gs_managed_key = true

eks_gs_managed_key = false {
    X := input.TEST_EKS[_]
    Y := input.TEST_KMS[_]
    encryption_config := X.cluster.encryptionConfig[_]
    encryption_config.provider.keyArn == Y.KeyMetadata.Arn
    Y.KeyMetadata.KeyManager != "CUSTOMER"
}

eks_gs_managed_key_err = "Ensure GS-managed encryption key is used for AWS EKS." {
    not eks_gs_managed_key
}

eks_gs_managed_key_metadata := {
    "Policy Code": "PR-AWS-CLD-EKS-010",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure GS-managed encryption key is used for AWS EKS.",
    "Policy Description": "It checks if encryption is enabled with a GS managed KMS CMK during the EKS cluster setup.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/eks.html#EKS.Client.describe_cluster"
}


#
# PR-AWS-CLD-EKS-011
# aws::eks::cluster
# aws::ec2::vpcendpoint

default eks_not_default_vpc = true

eks_not_default_vpc = false {
    X := input.TEST_EKS[_]
    Y := input.TEST_EC2_04[_]
    Vpc := Y.Vpcs[_]
    X.cluster.resourcesVpcConfig.vpcId == Vpc.VpcId
    Vpc.IsDefault == true
}

eks_not_default_vpc_err = "Ensure EKS cluster is not using the default VPC." {
    not eks_not_default_vpc
}

eks_not_default_vpc_metadata := {
    "Policy Code": "PR-AWS-CLD-EKS-011",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure EKS cluster is not using the default VPC.",
    "Policy Description": "It identifies AWS EKS clusters which are configured with the default VPC. It is recommended to use a VPC configuration based on your security and networking requirements. You should create your own EKS VPC instead of using the default, so that you can have full control over the cluster network.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/eks.html#EKS.Client.describe_cluster"
}