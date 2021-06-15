package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-cluster.html

#
# PR-AWS-0050-CFR
#

default eks_multiple_sg = null

aws_attribute_absence["eks_multiple_sg"] {
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
}

eks_multiple_sg_miss_err = "EKS cluster attribute SecurityGroupIds missing in the resource" {
    aws_attribute_absence["eks_multiple_sg"]
}

eks_multiple_sg_metadata := {
    "Policy Code": "PR-AWS-0050-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS EKS cluster control plane assigned multiple security groups",
    "Policy Description": "Amazon EKS strongly recommends that you use a dedicated security group for each cluster control plane (one per cluster). This policy checks the number of security groups assigned to your cluster's control plane and alerts if there are more than one.",
    "Compliance": [],
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-cluster.html"
}
