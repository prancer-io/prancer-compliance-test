package rule

available_false_choices := ["false", false]

#
# PR-AWS-TRF-RSH-001
#

default redshift_encrypt_key = null

aws_attribute_absence["redshift_encrypt_key"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_redshift_cluster"
    not resource.properties.kms_key_id
}

source_path[{"redshift_encrypt_key": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_redshift_cluster"
    not resource.properties.kms_key_id

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "kms_key_id"]
        ],
    }
}

aws_issue["redshift_encrypt_key"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_redshift_cluster"
    not startswith(lower(resource.properties.kms_key_id), "arn:")
}

source_path[{"redshift_encrypt_key": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_redshift_cluster"
    not startswith(lower(resource.properties.kms_key_id), "arn:")

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "kms_key_id"]
        ],
    }
}

aws_issue["redshift_encrypt_key"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_redshift_cluster"
    lower(resource.properties.encrypted) == "false"
}

source_path[{"redshift_encrypt_key": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_redshift_cluster"
    lower(resource.properties.encrypted) == "false"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "encrypted"]
        ],
    }
}

aws_bool_issue["redshift_encrypt_key"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_redshift_cluster"
    not resource.properties.encrypted
}

source_path[{"redshift_encrypt_key": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_redshift_cluster"
    not resource.properties.encrypted

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "encrypted"]
        ],
    }
}

redshift_encrypt_key {
    lower(input.resources[i].type) == "aws_redshift_cluster"
    not aws_issue["redshift_encrypt_key"]
    not aws_bool_issue["redshift_encrypt_key"]
    not aws_attribute_absence["redshift_encrypt_key"]
}

redshift_encrypt_key = false {
    aws_issue["redshift_encrypt_key"]
}

redshift_encrypt_key = false {
    aws_bool_issue["redshift_encrypt_key"]
}

redshift_encrypt_key = false {
    aws_attribute_absence["redshift_encrypt_key"]
}

redshift_encrypt_key_err = "AWS Redshift Cluster not encrypted using Customer Managed Key" {
    aws_issue["redshift_encrypt_key"]
} else = "AWS Redshift Cluster not encrypted using Customer Managed Key" {
    aws_bool_issue["redshift_encrypt_key"]
} else = "Redshift attribute kms_key_id missing in the resource" {
    aws_attribute_absence["redshift_encrypt_key"]
}

redshift_encrypt_key_metadata := {
    "Policy Code": "PR-AWS-TRF-RSH-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Redshift Cluster not encrypted using Customer Managed Key",
    "Policy Description": "This policy identifies Redshift Clusters which are encrypted with default KMS keys and not with Keys managed by Customer. It is a best practice to use customer managed KMS Keys to encrypt your Redshift databases data. Customer-managed CMKs give you more flexibility, including the ability to create, rotate, disable, define access control for, and audit the encryption keys used to help protect your data.",
    "Resource Type": "aws_redshift_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-redshift-cluster.html"
}

#
# PR-AWS-TRF-RSH-002
#

default redshift_public = null

aws_issue["redshift_public"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_redshift_cluster"
    lower(resource.properties.publicly_accessible) == "true"
}

source_path[{"redshift_public": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_redshift_cluster"
    lower(resource.properties.publicly_accessible) == "true"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "publicly_accessible"]
        ],
    }
}

aws_bool_issue["redshift_public"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_redshift_cluster"
    resource.properties.publicly_accessible
}

source_path[{"redshift_public": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_redshift_cluster"
    resource.properties.publicly_accessible

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "publicly_accessible"]
        ],
    }
}

redshift_public {
    lower(input.resources[i].type) == "aws_redshift_cluster"
    not aws_issue["redshift_public"]
    not aws_bool_issue["redshift_public"]
}

redshift_public = false {
    aws_issue["redshift_public"]
}

redshift_public = false {
    aws_bool_issue["redshift_public"]
}

redshift_public_err = "AWS Redshift clusters should not be publicly accessible" {
    aws_issue["redshift_public"]
} else = "AWS Redshift clusters should not be publicly accessible" {
    aws_bool_issue["redshift_public"]
}

redshift_public_metadata := {
    "Policy Code": "PR-AWS-TRF-RSH-002",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Redshift clusters should not be publicly accessible",
    "Policy Description": "This policy identifies AWS Redshift clusters which are accessible publicly.",
    "Resource Type": "aws_redshift_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-redshift-cluster.html"
}

#
# PR-AWS-TRF-RSH-007
#

default redshift_audit = null

aws_attribute_absence["redshift_audit"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_redshift_cluster"
    not resource.properties.logging
}

source_path[{"redshift_audit": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_redshift_cluster"
    not resource.properties.logging

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "logging"]
        ],
    }
}

aws_issue["redshift_audit"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_redshift_cluster"
    count(resource.properties.logging) == 0
}

source_path[{"redshift_audit": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_redshift_cluster"
    count(resource.properties.logging) == 0

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "logging"]
        ],
    }
}

aws_issue["redshift_audit"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_redshift_cluster"
    logging := resource.properties.logging[j]
    count([c | logging.bucket_name != null; c:= 1]) == 0
}

source_path[{"redshift_audit": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_redshift_cluster"
    logging := resource.properties.logging[j]
    count([c | logging.bucket_name != null; c:= 1]) == 0

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "logging", j, "bucket_name"]
        ],
    }
}

aws_issue["redshift_audit"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_redshift_cluster"
    logging := resource.properties.logging[j]
    count(logging.bucket_name) == 0
}

source_path[{"redshift_audit": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_redshift_cluster"
    logging := resource.properties.logging[j]
    count(logging.bucket_name) == 0

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "logging", j, "bucket_name"]
        ],
    }
}

redshift_audit {
    lower(input.resources[i].type) == "aws_redshift_cluster"
    not aws_issue["redshift_audit"]
    not aws_attribute_absence["redshift_audit"]
}

redshift_audit = false {
    aws_issue["redshift_audit"]
}

redshift_audit = false {
    aws_attribute_absence["redshift_audit"]
}

redshift_audit_err = "AWS Redshift database does not have audit logging enabled" {
    aws_issue["redshift_audit"]
} else = "Redshift attribute logging.bucket_name missing in the resource" {
    aws_attribute_absence["redshift_audit"]
}

redshift_audit_metadata := {
    "Policy Code": "PR-AWS-TRF-RSH-007",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Redshift database does not have audit logging enabled",
    "Policy Description": "Audit logging is not enabled by default in Amazon Redshift. When you enable logging on your cluster, Amazon Redshift creates and uploads logs to Amazon S3 that capture data from the creation of the cluster to the present time.",
    "Resource Type": "aws_redshift_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-redshift-cluster.html"
}

#
# PR-AWS-TRF-RSH-003
#

default redshift_require_ssl = null

aws_attribute_absence["redshift_require_ssl"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_redshift_parameter_group"
    not resource.properties.parameter
}

source_path[{"redshift_require_ssl": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_redshift_parameter_group"
    not resource.properties.parameter

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "parameter"]
        ],
    }
}

aws_issue["redshift_require_ssl"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_redshift_parameter_group"
    count([c | lower(resource.properties.parameter[_].name) == "require_ssl"; c := 1]) == 0
}

aws_issue["redshift_require_ssl"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_redshift_parameter_group"
    params = resource.properties.parameter[j]
    lower(params.name) == "require_ssl"
    lower(params.value) == "false"
}

source_path[{"redshift_require_ssl": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_redshift_parameter_group"
    params = resource.properties.parameter[j]
    lower(params.name) == "require_ssl"
    lower(params.value) == "false"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "parameter", j, "value"]
        ],
    }
}

aws_bool_issue["redshift_require_ssl"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_redshift_parameter_group"
    params = resource.properties.parameter[j]
    lower(params.name) == "require_ssl"
    not params.value
}

source_path[{"redshift_require_ssl": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_redshift_parameter_group"
    params = resource.properties.parameter[j]
    lower(params.name) == "require_ssl"
    not params.value

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "parameter", j, "value"]
        ],
    }
}

redshift_require_ssl {
    lower(input.resources[i].type) == "aws_redshift_parameter_group"
    not aws_issue["redshift_require_ssl"]
    not aws_bool_issue["redshift_require_ssl"]
    not aws_attribute_absence["redshift_require_ssl"]
}

redshift_require_ssl = false {
    aws_issue["redshift_require_ssl"]
}

redshift_require_ssl = false {
    aws_bool_issue["redshift_require_ssl"]
}

redshift_require_ssl = false {
    aws_attribute_absence["redshift_require_ssl"]
}

redshift_require_ssl_err = "AWS Redshift does not have require_ssl configured" {
    aws_issue["redshift_require_ssl"]
} else = "AWS Redshift does not have require_ssl configured" {
    aws_bool_issue["redshift_require_ssl"]
} else = "Redshift attribute properties missing in the resource" {
    aws_attribute_absence["redshift_require_ssl"]
}

redshift_require_ssl_metadata := {
    "Policy Code": "PR-AWS-TRF-RSH-003",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Redshift does not have require_ssl configured",
    "Policy Description": "This policy identifies Redshift databases in which data connection to and from is occurring on an insecure channel. SSL connections ensures the security of the data in transit.",
    "Resource Type": "aws_redshift_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-redshift-cluster.html"
}

#
# PR-AWS-TRF-RSH-004
#

default redshift_encrypt = null

aws_issue["redshift_encrypt"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_redshift_cluster"
    lower(resource.properties.encrypted) == "false"
}

source_path[{"redshift_encrypt": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_redshift_cluster"
    lower(resource.properties.encrypted) == "false"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "encrypted"]
        ],
    }
}

aws_bool_issue["redshift_encrypt"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_redshift_cluster"
    not resource.properties.encrypted
}

source_path[{"redshift_encrypt": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_redshift_cluster"
    not resource.properties.encrypted

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "encrypted"]
        ],
    }
}

redshift_encrypt {
    lower(input.resources[i].type) == "aws_redshift_cluster"
    not aws_issue["redshift_encrypt"]
    not aws_bool_issue["redshift_encrypt"]
}

redshift_encrypt = false {
    aws_issue["redshift_encrypt"]
}

redshift_encrypt = false {
    aws_bool_issue["redshift_encrypt"]
}

redshift_encrypt_err = "AWS Redshift instances are not encrypted" {
    aws_issue["redshift_encrypt"]
} else = "AWS Redshift instances are not encrypted" {
    aws_bool_issue["redshift_encrypt"]
}

redshift_encrypt_metadata := {
    "Policy Code": "PR-AWS-TRF-RSH-004",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Redshift instances are not encrypted",
    "Policy Description": "This policy identifies AWS Redshift instances which are not encrypted. These instances should be encrypted for clusters to help protect data at rest which otherwise can result in a data breach.",
    "Resource Type": "aws_redshift_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-redshift-cluster.html"
}

#
# PR-AWS-TRF-RSH-005
#

default redshift_allow_version_upgrade = null

aws_issue["redshift_allow_version_upgrade"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_redshift_cluster"
    lower(resource.properties.allow_version_upgrade) == "false"
}

source_path[{"redshift_allow_version_upgrade": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_redshift_cluster"
    lower(resource.properties.allow_version_upgrade) == "false"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "allow_version_upgrade"]
        ],
    }
}

aws_bool_issue["redshift_allow_version_upgrade"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_redshift_cluster"
    not resource.properties.allow_version_upgrade
}

source_path[{"redshift_allow_version_upgrade": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_redshift_cluster"
    not resource.properties.allow_version_upgrade

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "allow_version_upgrade"]
        ],
    }
}

redshift_allow_version_upgrade {
    lower(input.resources[i].type) == "aws_redshift_cluster"
    not aws_issue["redshift_allow_version_upgrade"]
    not aws_bool_issue["redshift_allow_version_upgrade"]
}


redshift_allow_version_upgrade = false {
    aws_issue["redshift_allow_version_upgrade"]
}

redshift_allow_version_upgrade = false {
    aws_bool_issue["redshift_allow_version_upgrade"]
}

redshift_allow_version_upgrade_err = "Ensure Redshift cluster allow version upgrade by default" {
    aws_issue["redshift_allow_version_upgrade"]
} else = "Ensure Redshift cluster allow version upgrade by default" {
    aws_bool_issue["redshift_allow_version_upgrade"]
}

redshift_allow_version_upgrade_metadata := {
    "Policy Code": "PR-AWS-TRF-RSH-005",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure Redshift cluster allow version upgrade by default",
    "Policy Description": "This policy identifies AWS Redshift instances which has not enabled AllowVersionUpgrade. major version upgrades can be applied during the maintenance window to the Amazon Redshift engine that is running on the cluster. When a new major version of the Amazon Redshift engine is released, you can request that the service automatically apply upgrades during the maintenance window to the Amazon Redshift engine that is running on your cluster.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-redshift-cluster.html#cfn-redshift-cluster-allowversionupgrade"
}

#
# PR-AWS-TRF-RSH-006
#

default redshift_deploy_vpc = null

aws_issue["redshift_deploy_vpc"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_redshift_cluster"
    count(resource.properties.cluster_subnet_group_name) == 0
}

source_path[{"redshift_deploy_vpc": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_redshift_cluster"
    count(resource.properties.cluster_subnet_group_name) == 0
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "cluster_subnet_group_name"]
        ],
    }
}


aws_issue["redshift_deploy_vpc"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_redshift_cluster"
    resource.properties.cluster_subnet_group_name == null
}

source_path[{"redshift_deploy_vpc": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_redshift_cluster"
    resource.properties.cluster_subnet_group_name == null
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "cluster_subnet_group_name"]
        ],
    }
}

aws_issue["redshift_deploy_vpc"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_redshift_cluster"
    not resource.properties.cluster_subnet_group_name
}

source_path[{"redshift_deploy_vpc": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_redshift_cluster"
    not resource.properties.cluster_subnet_group_name
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "cluster_subnet_group_name"]
        ],
    }
}

redshift_deploy_vpc {
    lower(input.resources[i].type) == "aws_redshift_cluster"
    not aws_issue["redshift_deploy_vpc"]
}

redshift_deploy_vpc = false {
    aws_issue["redshift_deploy_vpc"]
}


redshift_deploy_vpc_err = "Ensure Redshift is not deployed outside of a VPC" {
    aws_issue["redshift_deploy_vpc"]
}

redshift_deploy_vpc_metadata := {
    "Policy Code": "PR-AWS-TRF-RSH-006",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure Redshift is not deployed outside of a VPC",
    "Policy Description": "Ensure that your Redshift clusters are provisioned within the AWS EC2-VPC platform instead of EC2-Classic platform (outdated) for better flexibility and control over clusters security, traffic routing, availability and more.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/redshift_cluster"
}

#
# PR-AWS-TRF-RSH-008
#

default redshift_enhanced_vpc_routing = null

aws_issue["redshift_enhanced_vpc_routing"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_redshift_cluster"
    not resource.properties.enhanced_vpc_routing
}

aws_issue["redshift_enhanced_vpc_routing"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_redshift_cluster"
    resource.properties.enhanced_vpc_routing == available_false_choices[_]
}

redshift_enhanced_vpc_routing {
    lower(input.resources[i].type) == "aws_redshift_cluster"
    not aws_issue["redshift_enhanced_vpc_routing"]
}

redshift_enhanced_vpc_routing = false {
    aws_issue["redshift_enhanced_vpc_routing"]
}


redshift_enhanced_vpc_routing_err = "Ensure AWS Redshift - Enhanced VPC routing must be enabled." {
    aws_issue["redshift_enhanced_vpc_routing"]
}

redshift_enhanced_vpc_routing_metadata := {
    "Policy Code": "PR-AWS-TRF-RSH-008",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure AWS Redshift - Enhanced VPC routing must be enabled.",
    "Policy Description": "It is to check enhanced VPC routing is enabled or not forces all COPY and UNLOAD traffic between your cluster and your data repositories through your virtual private cloud (VPC) based on the Amazon VPC service.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/redshift_cluster"
}


#
# PR-AWS-TRF-RSH-011
#

default redshift_not_default_master_username = null

aws_issue["redshift_not_default_master_username"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_redshift_cluster"
    lower(resource.properties.master_username) == "awsuser"
}

redshift_not_default_master_username {
    lower(input.resources[i].type) == "aws_redshift_cluster"
    not aws_issue["redshift_not_default_master_username"]
}

redshift_not_default_master_username = false {
    aws_issue["redshift_not_default_master_username"]
}


redshift_not_default_master_username_err = "Ensure Redshift database clusters are not using default master username." {
    aws_issue["redshift_not_default_master_username"]
}

redshift_not_default_master_username_metadata := {
    "Policy Code": "PR-AWS-TRF-RSH-011",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure Redshift database clusters are not using default master username.",
    "Policy Description": "It is to check that Redshift clusters are not using default master username in order to reduce security risk.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/redshift_cluster"
}


#
# PR-AWS-TRF-RSH-012
#

default redshift_not_default_port = null

aws_issue["redshift_not_default_port"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_redshift_cluster"
    resource.properties.port == 5439
}

aws_issue["redshift_not_default_port"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_redshift_cluster"
    not resource.properties.port
}

redshift_not_default_port {
    lower(input.resources[i].type) == "aws_redshift_cluster"
    not aws_issue["redshift_not_default_port"]
}

redshift_not_default_port = false {
    aws_issue["redshift_not_default_port"]
}


redshift_not_default_port_err = "Ensure Redshift database clusters are not using default port(5439) for database connection." {
    aws_issue["redshift_not_default_port"]
}

redshift_not_default_port_metadata := {
    "Policy Code": "PR-AWS-TRF-RSH-012",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure Redshift database clusters are not using default port(5439) for database connection.",
    "Policy Description": "It is to check that Redshift cluster is not configured using default port to reduce security risks.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/redshift_cluster"
}


#
# PR-AWS-TRF-RSH-013
#

default redshift_automated_backup = null

aws_issue["redshift_automated_backup"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_redshift_cluster"
    resource.properties.automated_snapshot_retention_period == 0
}

redshift_automated_backup {
    lower(input.resources[i].type) == "aws_redshift_cluster"
    not aws_issue["redshift_automated_backup"]
}

redshift_automated_backup = false {
    aws_issue["redshift_automated_backup"]
}


redshift_automated_backup_err = "Ensure automated backups are enabled for Redshift cluster." {
    aws_issue["redshift_automated_backup"]
}

redshift_automated_backup_metadata := {
    "Policy Code": "PR-AWS-TRF-RSH-013",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure automated backups are enabled for Redshift cluster.",
    "Policy Description": "It is to check automated backup is turned on in order to recover data in the event of failures.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/redshift_cluster"
}