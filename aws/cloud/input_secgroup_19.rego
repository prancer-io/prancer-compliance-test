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
    # lower(input.Type) == "aws::ec2::securitygroup"
    ingress := input.SecurityGroups[_].IpPermissions[_]
    port := common_ports[_]
    ingress.IpRanges[_].CidrIp == "0.0.0.0/0"
    to_number(ingress.FromPort) <= port
    to_number(ingress.ToPort) >= port
}

rulepass = false {
    # lower(input.Type) == "aws::ec2::securitygroup"
    ingress := input.SecurityGroups[_].IpPermissions[_]
    port := common_ports[_]
    ingress.Ipv6Ranges[_].CidrIpv6="::/0"
    to_number(ingress.FromPort) <= port
    to_number(ingress.ToPort) >= port
}

metadata := {
    "Policy Code": "PR-AWS-0177",
    "Type": "Cloud",
    "Product": "AWS",
    "Language": "Cloud",
    "Policy Title": "AWS Security Groups allow internet traffic to ports which are not commonly used",
    "Policy Description": "This policy identifies security groups which are exposing ports to the internet that are not covered in other policies. It is recommended that Global permission be reduced as much as possible. Ports excluded from this policy are; 20, 21, 22, 23, 25, 53, 80, 135, 137, 138, 139, 443, 445, 1433, 1434, 3306, 3389, 4333 and 5432 which are covered in other policies.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeSecurityGroups.html"
}
