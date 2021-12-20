package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-cluster.html

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
# PR-AWS-CFR-EKS-004
#

default eks_encryption_kms = null

eks_encryption_kms {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::eks::cluster"
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
