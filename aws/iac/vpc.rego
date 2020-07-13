package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-subnet.html

#
# Id: 184
#

default vpc_subnet_autoip = null

vpc_subnet_autoip {
    lower(input.Type) == "aws::ec2::subnet"
    input.Properties.MapPublicIpOnLaunch == false
}

vpc_subnet_autoip {
    lower(input.Type) == "aws::ec2::subnet"
    not input.Properties.MapPublicIpOnLaunch
}

vpc_subnet_autoip = false {
    lower(input.Type) == "aws::ec2::subnet"
    input.Properties.MapPublicIpOnLaunch == true
}

vpc_subnet_autoip_err = "AWS VPC subnets should not allow automatic public IP assignment" {
    vpc_subnet_autoip == false
}
