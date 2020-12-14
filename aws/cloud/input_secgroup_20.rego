#
# PR-AWS-0178
#

package rule

default rulepass = true

# API: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeSecurityGroups.html

rulepass = false {
   ingress := input.SecurityGroups[_].IpPermissions[_]
   ingress.IpProtocol == "-1"
   ingress.IpRanges[_].CidrIp == "0.0.0.0/0"
}

rulepass = false {
   ingress := input.SecurityGroups[_].IpPermissions[_]
   ingress.IpProtocol == "-1"
   ingress.Ipv6Ranges[_].CidrIpv6="::/0"
}
