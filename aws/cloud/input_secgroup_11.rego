package rule

default rulepass = true

# API: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeSecurityGroups.html
# ID: 169

rulepass = false {
   ingress := input.SecurityGroups[_].IpPermissions[_]
   ingress.IpRanges[_].CidrIp == "0.0.0.0/0"
   to_number(ingress.FromPort) <= 25
   to_number(ingress.ToPort) >= 25
}

rulepass = false {
   ingress := input.SecurityGroups[_].IpPermissions[_]
   ingress.Ipv6Ranges[_].CidrIpv6="::/0"
   to_number(ingress.FromPort) <= 25
   to_number(ingress.ToPort) >= 25
}
