package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-cluster.html

#
# PR-AWS-0050-TRF
#

default eks_multiple_sg = null

aws_attribute_absence["eks_multiple_sg"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_eks_cluster"
    not resource.properties.vpc_config.security_group_ids
}

aws_issue["eks_multiple_sg"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_eks_cluster"
    count(resource.properties.vpc_config.security_group_ids) > 1
}

eks_multiple_sg {
    lower(input.resources[_].type) == "aws_eks_cluster"
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

eks_multiple_sg_miss_err = "EKS cluster attribute security_group_ids missing in the resource" {
    aws_attribute_absence["eks_multiple_sg"]
}
