package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-cluster.html

#
# Id: 50
#

default eks_multiple_sg = null

eks_multiple_sg {
    lower(input.Type) == "aws::eks::cluster"
    count(input.Properties.ResourcesVpcConfig.SecurityGroupIds) == 1
}

eks_multiple_sg = false {
    lower(input.Type) == "aws::eks::cluster"
    count(input.Properties.ResourcesVpcConfig.SecurityGroupIds) > 1
}

eks_multiple_sg_err = "AWS EKS cluster control plane assigned multiple security groups" {
    eks_multiple_sg == false
}
