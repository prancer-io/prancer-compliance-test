#
# PR-AWS-0035
#

package rule
default rulepass = false

# API Documentation: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeSecurityGroups.html

rulepass = true {
    lower(input.Type) == "aws::ec2::securitygroup"
    count(uphold) == 0
}

metadata := {
    "Policy Code": "PR-AWS-0035",
    "Type": "Cloud",
    "Product": "AWS",
    "Language": "Cloud",
    "Policy Title": "AWS Default Security Group does not restrict all traffic",
    "Policy Description": "This policy identifies the default security group which does not restrict all inbound and outbound traffic. A VPC comes with a default security group whose initial configuration deny all inbound traffic from internet and allow all outbound traffic. If you do not specify a security group when you launch an instance, the instance is automatically assigned to this default security group. As a result, the instance may accidentally send outbound traffic.",
    "Compliance": ["CIS","CSA-CCM","GDPR","HITRUST","NIST 800","SOC 2"],
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeSecurityGroups.html"
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