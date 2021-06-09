#
# PR-AWS-0044
#

package rule

default rulepass = true

# API Documentation: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstances.html

rulepass = false {
    lower(input.Type) == "aws::ec2::instance"
    instance := input.Reservations[_].Instances[_]
    instance.PublicIpAddress
    instance.SecurityGroups[_].IpPermissionsEgress[_].IpRanges[_].CidrIp == "0.0.0.0/0"
}

rulepass = false {
    lower(input.Type) == "aws::ec2::instance"
    instance := input.Reservations[_].Instances[_]
    instance.PublicIpAddress
    instance.SecurityGroups[_].IpPermissionsEgress[_].Ipv6Ranges[_].CidrIpv6 == "::/0"
}

metadata := {
    "Policy Code": "PR-AWS-0044",
    "Type": "Cloud",
    "Product": "AWS",
    "Language": "Cloud",
    "Policy Title": "AWS EC2 instance allowing public IP in subnets",
    "Policy Description": "This policy identifies the EC2 intances which are allowing public IP in their subnets. This will allow traffic from the internet visible to EC2 instance. Therefore it's a best practice to ensure that there are no EC2 instances with Public IP which have Internet Access.",
    "Compliance": [],
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstances.html"
}
