#
# PR-AWS-0168
#

package rule

default rulepass = true

# API: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeSecurityGroups.html

rulepass = false {
   ingress := input.SecurityGroups[_].IpPermissions[_]
   ingress.IpRanges[_].CidrIp == "0.0.0.0/0"
   to_number(ingress.FromPort) <= 3389
   to_number(ingress.ToPort) >= 3389
}

rulepass = false {
   ingress := input.SecurityGroups[_].IpPermissions[_]
   ingress.Ipv6Ranges[_].CidrIpv6="::/0"
   to_number(ingress.FromPort) <= 3389
   to_number(ingress.ToPort) >= 3389
}
