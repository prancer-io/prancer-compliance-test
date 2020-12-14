#
# PR-AWS-0035
#

package rule
default rulepass = false

# API Documentation: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeSecurityGroups.html

rulepass = true {                                      
   count(uphold) == 0
}

uphold["IpPermissions_CidrIp"] {
	input.SecurityGroups[_].IpPermissions[_].IpRanges[_].CidrIp="0.0.0.0/0"
}

uphold["IpPermissions_CidrIpv6"] {
	input.SecurityGroups[_].IpPermissions[_].Ipv6Ranges[_].CidrIpv6="::/0"
}

uphold["IpPermissionsEgress_CidrIp"] {
	input.SecurityGroups[_].IpPermissionsEgress[_].IpRanges[_].CidrIp="0.0.0.0/0"
}

uphold["IpPermissionsEgress_CidrIpV6"] {
	input.SecurityGroups[_].IpPermissionsEgress[_].Ipv6Ranges[_].CidrIpV6="::/0"
}