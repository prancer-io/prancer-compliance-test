#
# PR-AWS-0167
#

package rule

default rulepass = true

# API: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeSecurityGroups.html

rulepass = false {
    # lower(input.Type) == "aws::ec2::securitygroup"
    ingress := input.SecurityGroups[_].IpPermissions[_]
    ingress.IpRanges[_].CidrIp == "0.0.0.0/0"
    to_number(ingress.FromPort) <= 5432
    to_number(ingress.ToPort) >= 5432
}

rulepass = false {
    # lower(input.Type) == "aws::ec2::securitygroup"
    ingress := input.SecurityGroups[_].IpPermissions[_]
    ingress.Ipv6Ranges[_].CidrIpv6="::/0"
    to_number(ingress.FromPort) <= 5432
    to_number(ingress.ToPort) >= 5432
}

metadata := {
    "Policy Code": "PR-AWS-0167",
    "Type": "Cloud",
    "Product": "AWS",
    "Language": "Cloud",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to PostgreSQL port (5432)",
    "Policy Description": "This policy identifies the security groups which are exposing PostgreSQL port (5432) to the internet. It is recommended that Global permission to access the well known services PostgreSQL port (5432) should not be allowed in a security group.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeSecurityGroups.html"
}
