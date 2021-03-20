#
# PR-AWS-0046
#

package rule

default rulepass = true

# API Documentation: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstances.html

rulepass = false {
    lower(resource.Type) == "aws::ec2::instance"
    instance := input.Reservations[_].Instances[_]
    instance.PublicIpAddress
    instance.SecurityGroups[_].IpPermissions[_].IpRanges[_].CidrIp == "0.0.0.0/0"
}

rulepass = false {
    lower(resource.Type) == "aws::ec2::instance"
    instance := input.Reservations[_].Instances[_]
    instance.PublicIpAddress
    instance.SecurityGroups[_].IpPermissions[_].Ipv6Ranges[_].CidrIpv6 == "::/0"
}
