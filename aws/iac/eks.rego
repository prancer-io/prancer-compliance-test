package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-cluster.html

#
# PR-AWS-0050-CFR
#

default eks_multiple_sg = null

aws_attribute_absence["eks_multiple_sg"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::eks::cluster"
    not resource.Properties.ResourcesVpcConfig.SecurityGroupIds
}

aws_issue["eks_multiple_sg"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::eks::cluster"
    count(resource.Properties.ResourcesVpcConfig.SecurityGroupIds) > 1
}

eks_multiple_sg {
    lower(input.resources[_].Type) == "aws::eks::cluster"
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
