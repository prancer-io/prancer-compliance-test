package rule


#
# PR-AWS-TRF-VPC-001
#

default vpc_subnet_autoip = null

aws_issue["vpc_subnet_autoip"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_subnet"
    lower(resource.properties.map_public_ip_on_launch) == "true"
}

source_path[{"vpc_subnet_autoip": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_subnet"
    lower(resource.properties.map_public_ip_on_launch) == "true"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "map_public_ip_on_launch"]
        ],
    }
}

aws_bool_issue["vpc_subnet_autoip"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_subnet"
    resource.properties.map_public_ip_on_launch == true
}

source_path[{"vpc_subnet_autoip": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_subnet"
    resource.properties.map_public_ip_on_launch == true

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "map_public_ip_on_launch"]
        ],
    }
}

vpc_subnet_autoip {
    lower(input.resources[i].type) == "aws_subnet"
    not aws_issue["vpc_subnet_autoip"]
    not aws_bool_issue["vpc_subnet_autoip"]
}

vpc_subnet_autoip = false {
    aws_issue["vpc_subnet_autoip"]
}

vpc_subnet_autoip = false {
    aws_bool_issue["vpc_subnet_autoip"]
}

vpc_subnet_autoip_err = "AWS VPC subnets should not allow automatic public IP assignment" {
    aws_issue["vpc_subnet_autoip"]
} else = "AWS VPC subnets should not allow automatic public IP assignment" {
    aws_bool_issue["vpc_subnet_autoip"]
}

vpc_subnet_autoip_metadata := {
    "Policy Code": "PR-AWS-TRF-VPC-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS VPC subnets should not allow automatic public IP assignment",
    "Policy Description": "This policy identifies VPC subnets which allow automatic public IP assignment. VPC subnet is a part of the VPC having its own rules for traffic. Assigning the Public IP to the subnet automatically (on launch) can accidentally expose the instances within this subnet to internet and should be edited to 'No' post creation of the Subnet.",
    "Resource Type": "aws_subnet",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-subnet.html"
}