#
# PR-AWS-0177
#

package rule

default rulepass = true

# API: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeSecurityGroups.html

common_ports := [
    20, 21, 22, 23, 25, 53, 80, 135, 137, 138, 139, 443, 445, 1433, 1434, 3306, 3389, 4333, 5432
]

rulepass = false {
   ingress := input.SecurityGroups[_].IpPermissions[_]
   port := common_ports[_]
   ingress.IpRanges[_].CidrIp == "0.0.0.0/0"
   to_number(ingress.FromPort) <= port
   to_number(ingress.ToPort) >= port
}

rulepass = false {
   ingress := input.SecurityGroups[_].IpPermissions[_]
   port := common_ports[_]
   ingress.Ipv6Ranges[_].CidrIpv6="::/0"
   to_number(ingress.FromPort) <= port
   to_number(ingress.ToPort) >= port
}
