package rule


#
# PR-AWS-TRF-EKS-001
#

default eks_multiple_sg = null

aws_attribute_absence["eks_multiple_sg"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_eks_cluster"
    not resource.properties.vpc_config
}

source_path[{"eks_multiple_sg": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_eks_cluster"
    not resource.properties.vpc_config

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "vpc_config"]
        ],
    }
}

aws_attribute_absence["eks_multiple_sg"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_eks_cluster"
    vpc_config := resource.properties.vpc_config[j]
    not vpc_config.security_group_ids
}

source_path[{"eks_multiple_sg": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_eks_cluster"
    vpc_config := resource.properties.vpc_config[j]
    not vpc_config.security_group_ids

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "vpc_config", j, "security_group_ids"]
        ],
    }
}

aws_issue["eks_multiple_sg"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_eks_cluster"
    vpc_config := resource.properties.vpc_config[j]
    count(vpc_config.security_group_ids) != 1
}

source_path[{"eks_multiple_sg": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_eks_cluster"
    vpc_config := resource.properties.vpc_config[j]
    count(vpc_config.security_group_ids) != 1

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "vpc_config", j, "security_group_ids"]
        ],
    }
}

eks_multiple_sg {
    lower(input.resources[i].type) == "aws_eks_cluster"
    not aws_issue["eks_multiple_sg"]
    not aws_attribute_absence["eks_multiple_sg"]
}

eks_multiple_sg = false {
    aws_issue["eks_multiple_sg"]
}

eks_multiple_sg = false {
    aws_attribute_absence["eks_multiple_sg"]
}

eks_multiple_sg_err = "AWS EKS cluster control plane assigned multiple security groups" {
    aws_issue["eks_multiple_sg"]
} else = "EKS cluster attribute security_group_ids missing in the resource" {
    aws_attribute_absence["eks_multiple_sg"]
}

eks_multiple_sg_metadata := {
    "Policy Code": "PR-AWS-TRF-EKS-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS EKS cluster control plane assigned multiple security groups",
    "Policy Description": "Amazon EKS strongly recommends that you use a dedicated security group for each cluster control plane (one per cluster). This policy checks the number of security groups assigned to your cluster's control plane and alerts if there are more than one.",
    "Resource Type": "aws_eks_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-cluster.html"
}

#
# PR-AWS-TRF-EKS-002
#

default eks_version = null

aws_issue["eks_version"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_eks_cluster"
    startswith(lower(resource.properties.version), "1.9.")
}

source_path[{"eks_version": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_eks_cluster"
    startswith(lower(resource.properties.version), "1.9.")

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "version"]
        ],
    }
}

eks_version {
    lower(input.resources[i].type) == "aws_eks_cluster"
    not aws_issue["eks_version"]
}

eks_version = false {
    aws_issue["eks_version"]
}

eks_version_err = "AWS EKS unsupported Master node version." {
    aws_issue["eks_version"]
}
eks_version_metadata := {
    "Policy Code": "PR-AWS-TRF-EKS-002",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS EKS unsupported Master node version.",
    "Policy Description": "Ensure your EKS Master node version is supported. This policy checks your EKS master node version and generates an alert if the version running is unsupported.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-cluster.html#cfn-eks-cluster-version"
}