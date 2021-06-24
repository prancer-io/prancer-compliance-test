#
# PR-AWS-0046
#

package rule

default rulepass = true

# API Documentation: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstances.html

rulepass = false {
    # lower(input.Type) == "aws::ec2::instance"
    instance := input.Reservations[_].Instances[_]
    instance.PublicIpAddress
    instance.SecurityGroups[_].IpPermissions[_].IpRanges[_].CidrIp == "0.0.0.0/0"
}

rulepass = false {
    # lower(input.Type) == "aws::ec2::instance"
    instance := input.Reservations[_].Instances[_]
    instance.PublicIpAddress
    instance.SecurityGroups[_].IpPermissions[_].Ipv6Ranges[_].CidrIpv6 == "::/0"
}

metadata := {
    "Policy Code": "PR-AWS-0046",
    "Type": "Cloud",
    "Product": "AWS",
    "Language": "Cloud",
    "Policy Title": "AWS EC2 instances with Public IP and associated with Security Groups have Internet Access",
    "Policy Description": "This policy identifies AWS EC2 instances with Public IP and associated with Security Groups have Internet Access. EC2 instance receives a public IP address when launched in a default VPC security group (A security group acts as a virtual firewall for your instance to control inbound and outbound traffic.) and we don't assign a public IP address to instances launched in a non-default subnet. Therefore it's a best practice to ensure that there are no EC2 instances with Public IP that are associated with Security Groups which have Internet Access.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstances.html"
}
