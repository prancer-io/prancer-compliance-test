package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-cluster.html

#
# PR-AWS-0050-CFR
#

default eks_multiple_sg = null

aws_issue["eks_multiple_sg"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::eks::cluster"
    not resource.Properties.ResourcesVpcConfig.SecurityGroupIds
}

aws_issue["eks_multiple_sg"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::eks::cluster"
    count(resource.Properties.ResourcesVpcConfig.SecurityGroupIds) > 1
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
    "Policy Code": "PR-AWS-0050-CFR",
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
# PR-AWS-0051-CFR
#

default eks_public_access = null

aws_issue["eks_public_access"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::eks::cluster"
    lower(resource.Properties.ResourcesVpcConfig.EndpointPublicAccess) == "true"
}

aws_bool_issue["eks_public_access"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::eks::cluster"
    resource.Properties.ResourcesVpcConfig.EndpointPublicAccess == true
}

eks_public_access {
    lower(input.Resources[i].Type) == "aws::eks::cluster"
    not aws_issue["eks_public_access"]
    not aws_bool_issue["eks_public_access"]
}

eks_public_access = false {
    aws_issue["eks_public_access"]
}

eks_public_access = false {
    aws_bool_issue["eks_public_access"]
}

eks_public_access_err = "AWS EKS cluster endpoint access publicly enabled" {
    aws_issue["eks_public_access"]
} else = "AWS EKS cluster control plane assigned multiple security groups" {
    aws_bool_issue["eks_public_access"]
}

eks_public_access_metadata := {
    "Policy Code": "PR-AWS-0051-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS EKS cluster endpoint access publicly enabled",
    "Policy Description": "AWS EKS cluster endpoint access publicly enabled.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-cluster.html"
}
