package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-subnet.html

#
# PR-AWS-0184-CFR
#

default vpc_subnet_autoip = null

aws_issue["vpc_subnet_autoip"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::ec2::subnet"
    resource.Properties.MapPublicIpOnLaunch
}

vpc_subnet_autoip {
    lower(input.resources[_].Type) == "aws::ec2::subnet"
    not aws_issue["vpc_subnet_autoip"]
}

vpc_subnet_autoip = false {
    aws_issue["vpc_subnet_autoip"]
}

vpc_subnet_autoip_err = "AWS VPC subnets should not allow automatic public IP assignment" {
    aws_issue["vpc_subnet_autoip"]
}
