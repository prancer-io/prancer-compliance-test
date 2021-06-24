#
# PR-AWS-0165
#

package rule

default rulepass = true

# API: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeSecurityGroups.html

rulepass = false {
    # lower(input.json.Type) == "aws::ec2::securitygroup"
    ingress := input.json.SecurityGroups[_].IpPermissions[_]
    ingress.IpRanges[_].CidrIp == "0.0.0.0/0"
    to_number(ingress.FromPort) <= 137
    to_number(ingress.ToPort) >= 137
}

rulepass = false {
    # lower(input.json.Type) == "aws::ec2::securitygroup"
    ingress := input.json.SecurityGroups[_].IpPermissions[_]
    ingress.Ipv6Ranges[_].CidrIpv6="::/0"
    to_number(ingress.FromPort) <= 137
    to_number(ingress.ToPort) >= 137
}

metadata := {
    "Policy Code": "PR-AWS-0165",
    "Type": "Cloud",
    "Product": "AWS",
    "Language": "Cloud",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to NetBIOS port (137)",
    "Policy Description": "This policy identifies the security groups which are exposing NetBIOS port (137) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (137) should not be allowed in a security group.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeSecurityGroups.html"
}
