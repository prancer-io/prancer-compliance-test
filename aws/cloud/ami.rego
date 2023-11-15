package rule

has_property(parent_object, target_property) { 
	_ = parent_object[target_property]
}

#
# PR-AWS-CLD-AMI-001
#

default ami_public_access_disabled = true

ami_public_access_disabled = false {
    images := input.Images[_]
    images.Public
}

ami_public_access_disabled_err = "AMI public access currently not disabled. Please remediate." {
    not ami_public_access_disabled
}

ami_public_access_disabled_metadata := {
    "Policy Code": "PR-AWS-CLD-AMI-001",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AMI public access should be disabled",
    "Policy Description": "This policy identifies AWS AMIs which are owned by the AWS account and are public accessible. Amazon Machine Image (AMI) provides information to launch an instance in the cloud. The AMIs may contain proprietary customer information and should be accessible only to authorized internal users. It is recommended to not publicly shared with the other AWS accounts in order to avoid sensitive data exposure. If required, AMI images should only be shared with relevant AWS accounts without making them public.",
    "Resource Type": "",
    "Policy Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2/client/describe_images.html",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeImages.html"
}


#
# PR-AWS-CLD-AMI-002
#

default ami_not_infected_with_mining_malware = true

ami_not_infected_with_mining_malware = false {
    # lower(resource.Type) == "aws::ec2::instance"
    images := input.Images[_]
    contains(lower(images.Platform), "windows")
    contains(lower(images.ImageId), "ami-1e542176")
}

ami_not_infected_with_mining_malware_err = "AMI currently infected with mining malware. Please remediate." {
    not ami_not_infected_with_mining_malware
}

ami_not_infected_with_mining_malware_metadata := {
    "Policy Code": "PR-AWS-CLD-EC2-007",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AMI is not infected with mining malware",
    "Policy Description": "This policy identifies AMIs that are infected with mining malware. As per research, AWS Community AMI Windows 2008 hosted by an unverified vendor containing malicious code running an unidentified crypto (Monero) miner. It is recommended to delete such AMIs to protect from malicious activity and attack blast.",
    "Resource Type": "",
    "Policy Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2/client/describe_images.html",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeImages.html"
}


#
# PR-AWS-CLD-AMI-003
#

default ami_not_older_than_180_days = true

ami_not_older_than_180_days = false {
    images := input.Images[_]
	(time.parse_rfc3339_ns(images.CreationDate) - time.now_ns()) > 15552000000000000
}

ami_not_older_than_180_days_err = "180 days older AMIs found. Please remediate." {
    not ami_not_older_than_180_days
}

ami_not_older_than_180_days_metadata := {
    "Policy Code": "PR-AWS-CLD-AMI-003",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure to recreate AMIs older than 180 days",
    "Policy Description": "Effectively managing the lifecycle of Amazon Machine Images (AMIs) is crucial for maintaining a secure and efficient AWS environment. By proactively checking for AMIs older than 180 days, you can identify and address potential security vulnerabilities that may arise due to outdated software or configurations.",
    "Resource Type": "",
    "Policy Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2/client/describe_images.html",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeImages.html",
}