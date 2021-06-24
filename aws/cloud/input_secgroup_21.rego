#
# PR-AWS-0179
#

package rule

default rulepass = true

# API: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeSecurityGroups.html

rulepass = false {
    # lower(input.json.Type) == "aws::ec2::securitygroup"
    ingress := input.json.SecurityGroups[_].IpPermissions[_]
    ingress.IpRanges[_].CidrIp == "0.0.0.0/0"
}

rulepass = false {
    # lower(input.json.Type) == "aws::ec2::securitygroup"
    ingress := input.json.SecurityGroups[_].IpPermissions[_]
    ingress.Ipv6Ranges[_].CidrIpv6="::/0"
}

metadata := {
    "Policy Code": "PR-AWS-0179",
    "Type": "Cloud",
    "Product": "AWS",
    "Language": "Cloud",
    "Policy Title": "AWS Security groups allow internet traffic",
    "Policy Description": "This policy identifies that Security Groups do not allow all traffic from internet. A Security Group acts as a virtual firewall that controls the traffic for one or more instances. Security groups should have restrictive ACLs to only allow incoming traffic from specific IPs to specific ports where the application is listening for connections.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeSecurityGroups.html"
}
