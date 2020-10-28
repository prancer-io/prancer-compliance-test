package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-subnet.html

#
# Id: 184
#

default vpc_subnet_autoip = null

aws_issue["vpc_subnet_autoip"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_subnet"
    resource.properties.map_public_ip_on_launch
}

vpc_subnet_autoip {
    lower(input.json.resources[_].type) == "aws_subnet"
    not aws_issue["vpc_subnet_autoip"]
}

vpc_subnet_autoip = false {
    aws_issue["vpc_subnet_autoip"]
}

vpc_subnet_autoip_err = "AWS VPC subnets should not allow automatic public IP assignment" {
    aws_issue["vpc_subnet_autoip"]
}
