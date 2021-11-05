package rule


#
# PR-AWS-TRF-EBS-001
#

default ebs_encrypt = null

aws_issue["ebs_encrypt"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ebs_volume"
    lower(resource.properties.encrypted) == "false"
}

source_path[{"ebs_encrypt": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ebs_volume"
    lower(resource.properties.encrypted) == "false"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "encrypted"]
        ],
    }
}

aws_bool_issue["ebs_encrypt"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ebs_volume"
    not resource.properties.encrypted
}

source_path[{"ebs_encrypt": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ebs_volume"
    not resource.properties.encrypted

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "encrypted"]
        ],
    }
}

ebs_encrypt {
    lower(input.resources[i].type) == "aws_ebs_volume"
    not aws_issue["ebs_encrypt"]
    not aws_bool_issue["ebs_encrypt"]
}

ebs_encrypt = false {
    aws_issue["ebs_encrypt"]
}

ebs_encrypt = false {
    aws_bool_issue["ebs_encrypt"]
}

ebs_encrypt_err = "AWS EBS volumes are not encrypted" {
    aws_issue["ebs_encrypt"]
} else = "AWS EBS volumes are not encrypted" {
    aws_bool_issue["ebs_encrypt"]
}

ebs_encrypt_metadata := {
    "Policy Code": "PR-AWS-TRF-EBS-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS EBS volumes are not encrypted",
    "Policy Description": "This policy identifies the EBS volumes which are not encrypted. The snapshots that you take of an encrypted EBS volume are also encrypted and can be moved between AWS Regions as needed. You cannot share encrypted snapshots with other AWS accounts and you cannot make them public. It is recommended that EBS volume should be encrypted.",
    "Resource Type": "aws_ebs_volume",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-ebs-volume.html"
}

#
# PR-AWS-TRF-EFS-001
#

default efs_kms = null

aws_attribute_absence["efs_kms"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_efs_file_system"
    not resource.properties.kms_key_id
}

source_path[{"efs_kms": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_efs_file_system"
    not resource.properties.kms_key_id

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "kms_key_id"]
        ],
    }
}

aws_issue["efs_kms"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_efs_file_system"
    resource.properties.kms_key_id == null
}

source_path[{"efs_kms": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_efs_file_system"
    resource.properties.kms_key_id == null

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "kms_key_id"]
        ],
    }
}

aws_issue["efs_kms"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_efs_file_system"
    resource.properties.kms_key_id != null
    not startswith(resource.properties.kms_key_id, "arn:")
}

source_path[{"efs_kms": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_efs_file_system"
    resource.properties.kms_key_id != null
    not startswith(resource.properties.kms_key_id, "arn:")

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "kms_key_id"]
        ],
    }
}

aws_issue["efs_kms"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_efs_file_system"
    lower(resource.properties.encrypted) == "false"
}

source_path[{"efs_kms": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_efs_file_system"
    lower(resource.properties.encrypted) == "false"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "encrypted"]
        ],
    }
}

aws_bool_issue["efs_kms"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_efs_file_system"
    not resource.properties.encrypted
}


efs_kms {
    lower(input.resources[i].type) == "aws_efs_file_system"
    not aws_issue["efs_kms"]
    not aws_bool_issue["efs_kms"]
    not aws_attribute_absence["efs_kms"]
}

efs_kms = false {
    aws_issue["efs_kms"]
}

efs_kms = false {
    aws_bool_issue["efs_kms"]
}

efs_kms = false {
    aws_attribute_absence["efs_kms"]
}

efs_kms_err = "AWS Elastic File System (EFS) not encrypted using Customer Managed Key" {
    aws_issue["efs_kms"]
} else = "AWS Elastic File System (EFS) not encrypted using Customer Managed Key" {
    aws_bool_issue["efs_kms"]
} else = "EFS attribute kms_key_id missing in the resource" {
    aws_attribute_absence["efs_kms"]
}

efs_kms_metadata := {
    "Policy Code": "PR-AWS-TRF-EFS-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Elastic File System (EFS) not encrypted using Customer Managed Key",
    "Policy Description": "This policy identifies Elastic File Systems (EFSs) which are encrypted with default KMS keys and not with Keys managed by Customer. It is a best practice to use customer managed KMS Keys to encrypt your EFS data. It gives you full control over the encrypted data.",
    "Resource Type": "aws_efs_file_system",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-efs-filesystem.html"
}

#
# PR-AWS-TRF-EFS-002
#

default efs_encrypt = null

aws_issue["efs_encrypt"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_efs_file_system"
    lower(resource.properties.encrypted) == "false"
}

source_path[{"efs_encrypt": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_efs_file_system"
    lower(resource.properties.encrypted) == "false"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "encrypted"]
        ],
    }
}

aws_bool_issue["efs_encrypt"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_efs_file_system"
    not resource.properties.encrypted
}

source_path[{"efs_encrypt": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_efs_file_system"
    not resource.properties.encrypted

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "encrypted"]
        ],
    }
}

efs_encrypt {
    lower(input.resources[i].type) == "aws_efs_file_system"
    not aws_issue["efs_encrypt"]
    not aws_bool_issue["efs_encrypt"]
}

efs_encrypt = false {
    aws_issue["efs_encrypt"]
}

efs_encrypt = false {
    aws_bool_issue["efs_encrypt"]
}

efs_encrypt_err = "AWS Elastic File System (EFS) with encryption for data at rest disabled" {
    aws_issue["efs_encrypt"]
} else = "AWS Elastic File System (EFS) with encryption for data at rest disabled" {
    aws_bool_issue["efs_encrypt"]
}

efs_encrypt_metadata := {
    "Policy Code": "PR-AWS-TRF-EFS-002",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Elastic File System (EFS) with encryption for data at rest disabled",
    "Policy Description": "This policy identifies Elastic File Systems (EFSs) for which encryption for data at rest disabled. It is highly recommended to implement at-rest encryption in order to prevent unauthorized users from reading sensitive data saved to EFS.",
    "Resource Type": "aws_efs_file_system",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-efs-filesystem.html"
}

#
# PR-AWS-TRF-S3-001
#

default s3_accesslog = null

aws_attribute_absence["s3_accesslog"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket"
    not resource.properties.logging
}

source_path[{"s3_accesslog": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket"
    not resource.properties.logging

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "logging"]
        ],
    }
}

aws_attribute_absence["s3_accesslog"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket"
    count(resource.properties.logging) == 0
}

source_path[{"s3_accesslog": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket"
    count(resource.properties.logging) == 0

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "logging"]
        ],
    }
}

aws_attribute_absence["s3_accesslog"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket"
    logging := resource.properties.logging[j]
    not logging.target_prefix
}

source_path[{"s3_accesslog": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket"
    logging := resource.properties.logging[j]
    not logging.target_prefix

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "logging", j, "target_prefix"]
        ],
    }
}

aws_issue["s3_accesslog"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket"
    logging := resource.properties.logging[j]
    count(logging.target_bucket) == 0
}

source_path[{"s3_accesslog": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket"
    logging := resource.properties.logging[j]
    count(logging.target_bucket) == 0

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "logging", j, "target_prefix"]
        ],
    }
}

s3_accesslog {
    lower(input.resources[i].type) == "aws_s3_bucket"
    not aws_issue["s3_accesslog"]
    not aws_attribute_absence["s3_accesslog"]
}

s3_accesslog = false {
    aws_issue["s3_accesslog"]
}

s3_accesslog = false {
    aws_attribute_absence["s3_accesslog"]
}

s3_accesslog_err = "AWS Access logging not enabled on S3 buckets" {
    aws_issue["s3_accesslog"]
} else = "S3 Bucket attribute target_bucket/target_prefix missing in the resource" {
    aws_attribute_absence["s3_accesslog"]
}

s3_accesslog_metadata := {
    "Policy Code": "PR-AWS-TRF-S3-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Access logging not enabled on S3 buckets",
    "Policy Description": "Checks for S3 buckets without access logging turned on. Access logging allows customers to view complete audit trail on sensitive workloads such as S3 buckets. It is recommended that Access logging is turned on for all S3 buckets to meet audit PR-AWS-TRF-S3-001-DESC compliance requirement",
    "Resource Type": "aws_s3_bucket_policy",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html"
}

#
# PR-AWS-TRF-S3-002
#

default s3_acl_delete = null

aws_attribute_absence["s3_acl_delete"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket_policy"
    not resource.properties.policy.Statement
}

source_path[{"s3_acl_delete": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket_policy"
    not resource.properties.policy.Statement

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "policy", "Statement"]
        ],
    }
}

aws_issue["s3_acl_delete"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket_policy"
    stat := resource.properties.policy.Statement[j]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    lower(stat.Action) == "s3:*"
}

source_path[{"s3_acl_delete": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket_policy"
    stat := resource.properties.policy.Statement[j]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    lower(stat.Action) == "s3:*"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "policy", "Statement", j, "Action"]
        ],
    }
}

aws_issue["s3_acl_delete"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket_policy"
    stat := resource.properties.policy.Statement[j]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    startswith(lower(stat.Action),"s3:delete")
}

source_path[{"s3_acl_delete": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket_policy"
    stat := resource.properties.policy.Statement[j]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    startswith(lower(stat.Action),"s3:delete")

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "policy", "Statement", j, "Action"]
        ],
    }
}

aws_issue["s3_acl_delete"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket_policy"
    stat := resource.properties.policy.Statement[j]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    startswith(lower(stat.Action[k]),"s3:delete")
}

source_path[{"s3_acl_delete": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket_policy"
    stat := resource.properties.policy.Statement[j]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    startswith(lower(stat.Action[k]),"s3:delete")

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "policy", "Statement", j, "Action", k]
        ],
    }
}

s3_acl_delete {
    lower(input.resources[i].type) == "aws_s3_bucket_policy"
    not aws_issue["s3_acl_delete"]
    not aws_attribute_absence["s3_acl_delete"]
}

s3_acl_delete = false {
    aws_issue["s3_acl_delete"]
}

s3_acl_delete = false {
    aws_attribute_absence["s3_acl_delete"]
}

s3_acl_delete_err = "AWS S3 Bucket has Global DELETE Permissions enabled via bucket policy" {
    aws_issue["s3_acl_delete"]
} else = "S3 Policy attribute policy.Statement missing in the resource" {
    aws_attribute_absence["s3_acl_delete"]
}

s3_acl_delete_metadata := {
    "Policy Code": "PR-AWS-TRF-S3-002",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS S3 Bucket has Global DELETE Permissions enabled via bucket policy",
    "Policy Description": "This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to DELETE objects from a bucket. These permissions permit anyone, malicious or not, to DELETE objects from your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk loss or compromise of critical data by leaving this open.",
    "Resource Type": "aws_s3_bucket_policy",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html"
}

#
# PR-AWS-TRF-S3-003
#

default s3_acl_get = null

aws_attribute_absence["s3_acl_get"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket_policy"
    not resource.properties.policy.Statement
}

source_path[{"s3_acl_get": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket_policy"
    not resource.properties.policy.Statement

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "policy", "Statement"]
        ],
    }
}

aws_issue["s3_acl_get"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket_policy"
    stat := resource.properties.policy.Statement[j]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    lower(stat.Action) == "s3:*"
}

source_path[{"s3_acl_get": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket_policy"
    stat := resource.properties.policy.Statement[j]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    startswith(lower(stat.Action),"s3:get")

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "policy", "Statement", j, "Action"]
        ],
    }
}

aws_issue["s3_acl_get"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket_policy"
    stat := resource.properties.policy.Statement[j]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    startswith(lower(stat.Action),"s3:get")
}

source_path[{"s3_acl_get": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket_policy"
    stat := resource.properties.policy.Statement[j]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    startswith(lower(stat.Action),"s3:get")

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "policy", "Statement", j, "Action"]
        ],
    }
}

aws_issue["s3_acl_get"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket_policy"
    stat := resource.properties.policy.Statement[j]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    startswith(lower(stat.Action[k]),"s3:get")
}

source_path[{"s3_acl_get": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket_policy"
    stat := resource.properties.policy.Statement[j]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    startswith(lower(stat.Action[k]),"s3:delete")

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "policy", "Statement", j, "Action", k]
        ],
    }
}

s3_acl_get {
    lower(input.resources[i].type) == "aws_s3_bucket_policy"
    not aws_issue["s3_acl_get"]
    not aws_attribute_absence["s3_acl_get"]
}

s3_acl_get = false {
    aws_issue["s3_acl_get"]
}

s3_acl_get = false {
    aws_attribute_absence["s3_acl_get"]
}

s3_acl_get_err = "AWS S3 Bucket has Global get Permissions enabled via bucket policy" {
    aws_issue["s3_acl_get"]
} else = "S3 Policy attribute policy.Statement missing in the resource" {
    aws_attribute_absence["s3_acl_get"]
}

s3_acl_get_metadata := {
    "Policy Code": "PR-AWS-TRF-S3-003",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS S3 Bucket has Global GET Permissions enabled via bucket policy",
    "Policy Description": "This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to GET objects from a bucket. These permissions permit anyone, malicious or not, to GET objects from your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk loss or compromise of critical data by leaving this open.",
    "Resource Type": "aws_s3_bucket_policy",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html"
}

#
# PR-AWS-TRF-S3-004
#

default s3_acl_list = null

aws_attribute_absence["s3_acl_list"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket_policy"
    not resource.properties.policy.Statement
}

source_path[{"s3_acl_list": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket_policy"
    not resource.properties.policy.Statement

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "policy", "Statement"]
        ],
    }
}

aws_issue["s3_acl_list"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket_policy"
    stat := resource.properties.policy.Statement[j]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    lower(stat.Action) == "s3:*"
}

source_path[{"s3_acl_list": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket_policy"
    stat := resource.properties.policy.Statement[j]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    lower(stat.Action) == "s3:*"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "policy", "Statement", j, "Action"]
        ],
    }
}

aws_issue["s3_acl_list"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket_policy"
    stat := resource.properties.policy.Statement[j]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    startswith(lower(stat.Action),"s3:list")
}

source_path[{"s3_acl_list": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket_policy"
    stat := resource.properties.policy.Statement[j]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    startswith(lower(stat.Action),"s3:list")

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "policy", "Statement", j, "Action"]
        ],
    }
}

aws_issue["s3_acl_list"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket_policy"
    stat := resource.properties.policy.Statement[j]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    startswith(lower(stat.Action[k]),"s3:list")
}

source_path[{"s3_acl_list": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket_policy"
    stat := resource.properties.policy.Statement[j]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    startswith(lower(stat.Action[k]),"s3:list")

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "policy", "Statement", j, "Action", k]
        ],
    }
}

s3_acl_list {
    lower(input.resources[i].type) == "aws_s3_bucket_policy"
    not aws_issue["s3_acl_list"]
    not aws_attribute_absence["s3_acl_list"]
}

s3_acl_list = false {
    aws_issue["s3_acl_list"]
}

s3_acl_list = false {
    aws_attribute_absence["s3_acl_list"]
}

s3_acl_list_err = "AWS S3 Bucket has Global list Permissions enabled via bucket policy" {
    aws_issue["s3_acl_list"]
} else = "S3 Policy attribute policy.Statement missing in the resource" {
    aws_attribute_absence["s3_acl_list"]
}

s3_acl_list_metadata := {
    "Policy Code": "PR-AWS-TRF-S3-004",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS S3 Bucket has Global LIST Permissions enabled via bucket policy",
    "Policy Description": "This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to LIST objects from a bucket. These permissions permit anyone, malicious or not, to LIST objects from your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk loss or compromise of critical data by leaving this open.",
    "Resource Type": "aws_s3_bucket_policy",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html"
}

#
# PR-AWS-TRF-S3-005
#

default s3_acl_put = null

aws_attribute_absence["s3_acl_put"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket_policy"
    not resource.properties.policy.Statement
}

source_path[{"s3_acl_put": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket_policy"
    not resource.properties.policy.Statement

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "policy", "Statement"]
        ],
    }
}

aws_issue["s3_acl_put"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket_policy"
    stat := resource.properties.policy.Statement[j]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    lower(stat.Action) == "s3:*"
}

source_path[{"s3_acl_put": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket_policy"
    stat := resource.properties.policy.Statement[j]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    lower(stat.Action) == "s3:*"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "policy", "Statement", j, "Action"]
        ],
    }
}

aws_issue["s3_acl_put"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket_policy"
    stat := resource.properties.policy.Statement[j]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    startswith(lower(stat.Action),"s3:put")
}

source_path[{"s3_acl_put": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket_policy"
    stat := resource.properties.policy.Statement[j]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    startswith(lower(stat.Action),"s3:put")

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "policy", "Statement", j, "Action"]
        ],
    }
}

aws_issue["s3_acl_put"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket_policy"
    stat := resource.properties.policy.Statement[j]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    startswith(lower(stat.Action[k]),"s3:put")
}

source_path[{"s3_acl_put": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket_policy"
    stat := resource.properties.policy.Statement[j]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    startswith(lower(stat.Action[k]),"s3:put")

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "policy", "Statement", j, "Action", k]
        ],
    }
}

s3_acl_put {
    lower(input.resources[i].type) == "aws_s3_bucket_policy"
    not aws_issue["s3_acl_put"]
    not aws_attribute_absence["s3_acl_put"]
}

s3_acl_put = false {
    aws_issue["s3_acl_put"]
}

s3_acl_put = false {
    aws_attribute_absence["s3_acl_put"]
}

s3_acl_put_err = "AWS S3 Bucket has Global put Permissions enabled via bucket policy" {
    aws_issue["s3_acl_put"]
} else = "S3 Policy attribute policy.Statement missing in the resource" {
    aws_attribute_absence["s3_acl_put"]
}

s3_acl_put_metadata := {
    "Policy Code": "PR-AWS-TRF-S3-005",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS S3 Bucket has Global PUT Permissions enabled via bucket policy",
    "Policy Description": "This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to PUT objects into a bucket. These permissions permit anyone, malicious or not, to PUT objects into your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk compromise of critical data by leaving this open.",
    "Resource Type": "aws_s3_bucket_policy",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html"
}

#
# PR-AWS-TRF-S3-007
#

default s3_versioning = null

aws_attribute_absence["s3_versioning"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket"
    versioning := resource.properties.versioning[j]
    not versioning.enabled
}

source_path[{"s3_versioning": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket"
    versioning := resource.properties.versioning[j]
    not versioning.enabled

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "versioning", j, "enabled"]
        ],
    }
}

aws_issue["s3_versioning"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket"
    versioning := resource.properties.versioning[j]
    lower(versioning.enabled) == "false"
}

source_path[{"s3_versioning": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket"
    versioning := resource.properties.versioning[j]
    lower(versioning.enabled) == "false"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "versioning", j, "enabled"]
        ],
    }
}

aws_bool_issue["s3_versioning"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket"
    versioning := resource.properties.versioning[j]
    versioning.enabled == false
}

source_path[{"s3_versioning": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket"
    versioning := resource.properties.versioning[j]
    versioning.enabled == false

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "versioning", j, "enabled"]
        ],
    }
}

s3_versioning {
    lower(input.resources[i].type) == "aws_s3_bucket"
    not aws_issue["s3_versioning"]
    not aws_bool_issue["s3_versioning"]
    not aws_attribute_absence["s3_versioning"]
}

s3_versioning = false {
    aws_issue["s3_versioning"]
}

s3_versioning = false {
    aws_bool_issue["s3_versioning"]
}

s3_versioning = false {
    aws_attribute_absence["s3_versioning"]
}

s3_versioning_err = "AWS S3 Object Versioning is disabled" {
    aws_issue["s3_versioning"]
} else = "AWS S3 Object Versioning is disabled" {
    aws_bool_issue["s3_versioning"]
} else = "S3 Bucket attribute versioning.enabled missing in the resource" {
    aws_attribute_absence["s3_versioning"]
}

s3_versioning_metadata := {
    "Policy Code": "PR-AWS-TRF-S3-007",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS S3 Object Versioning is disabled",
    "Policy Description": "This policy identifies the S3 buckets which have Object Versioning disabled. S3 Object Versioning is an important capability in protecting your data within a bucket. Once you enable Object Versioning, you cannot remove it; you can suspend Object Versioning at any time on a bucket if you do not wish for it to persist. It is recommended to enable Object Versioning on S3.",
    "Resource Type": "aws_s3_bucket_policy",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html"
}

#
# PR-AWS-TRF-S3-009
#

default s3_transport = null

aws_attribute_absence["s3_transport"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket_policy"
    statement := resource.properties.policy.Statement[j]
    count([c | statement.Condition.StringLike["aws:SecureTransport"]; c := 1]) == 0
    count([c | statement.Condition.Bool["aws:SecureTransport"]; c := 1]) == 0
}

source_path[{"s3_transport": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket_policy"
    statement := resource.properties.policy.Statement[j]
    count([c | statement.Condition.StringLike["aws:SecureTransport"]; c := 1]) == 0
    count([c | statement.Condition.Bool["aws:SecureTransport"]; c := 1]) == 0

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "policy", "Statement", j, "Condition", "StringLike", "aws:SecureTransport"],
            ["resources", i, "properties", "policy", "Statement", j, "Condition", "Bool", "aws:SecureTransport"],
        ],
    }
}

aws_issue["s3_transport"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket_policy"
    statement := resource.properties.policy.Statement[j]
    statement.Condition.StringLike
    statement.Condition.StringLike["aws:SecureTransport"] == false
}

source_path[{"s3_transport": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket_policy"
    statement := resource.properties.policy.Statement[j]
    statement.Condition.StringLike
    statement.Condition.StringLike["aws:SecureTransport"] == false

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "policy", "Statement", j, "Condition", "StringLike", "aws:SecureTransport"]
        ],
    }
}

aws_bool_issue["s3_transport"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket_policy"
    statement := resource.properties.policy.Statement[j]
    statement.Condition.StringLike
    lower(statement.Condition.StringLike["aws:SecureTransport"]) == "false"
}

source_path[{"s3_transport": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket_policy"
    statement := resource.properties.policy.Statement[j]
    statement.Condition.StringLike
    lower(statement.Condition.StringLike["aws:SecureTransport"]) == "false"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "policy", "Statement", j, "Condition", "StringLike", "aws:SecureTransport"]
        ],
    }
}

aws_issue["s3_transport"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket_policy"
    statement := resource.properties.policy.Statement[j]
    statement.Condition.Bool
    statement.Condition.Bool["aws:SecureTransport"] == false
}

source_path[{"s3_transport": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket_policy"
    statement := resource.properties.policy.Statement[j]
    statement.Condition.Bool
    statement.Condition.Bool["aws:SecureTransport"] == false

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "policy", "Statement", j, "Condition", "Bool", "aws:SecureTransport"]
        ],
    }
}

aws_bool_issue["s3_transport"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket_policy"
    statement := resource.properties.policy.Statement[j]
    statement.Condition.Bool
    lower(statement.Condition.Bool["aws:SecureTransport"]) == "false"
}

source_path[{"s3_transport": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket_policy"
    statement := resource.properties.policy.Statement[j]
    statement.Condition.Bool
    lower(statement.Condition.Bool["aws:SecureTransport"]) == "false"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "policy", "Statement", j, "Condition", "Bool", "aws:SecureTransport"]
        ],
    }
}

s3_transport {
    lower(input.resources[i].type) == "aws_s3_bucket_policy"
    not aws_issue["s3_transport"]
    not aws_bool_issue["s3_transport"]
    not aws_attribute_absence["s3_transport"]
}

s3_transport = false {
    aws_issue["s3_transport"]
}

s3_transport = false {
    aws_bool_issue["s3_transport"]
}


s3_transport = false {
    aws_attribute_absence["s3_transport"]
}

s3_transport_err = "AWS S3 bucket not configured with secure data transport policy" {
    aws_issue["s3_transport"]
} else = "AWS S3 bucket not configured with secure data transport policy" {
    aws_bool_issue["s3_transport"]
} else = "S3 Policy attribute Condition SecureTransport missing in the resource" {
    aws_attribute_absence["s3_transport"]
}

s3_transport_metadata := {
    "Policy Code": "PR-AWS-TRF-S3-009",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS S3 bucket not configured with secure data transport policy",
    "Policy Description": "This policy identifies S3 buckets which are not configured with secure data transport policy. AWS S3 buckets should enforce encryption of data over the network using Secure Sockets Layer (SSL). It is recommended to add a bucket policy that explicitly denies (Effect: Deny) all access (Action: s3:*) from anybody who browses (Principal: *) to Amazon S3 objects within an Amazon S3 bucket if they are not accessed through HTTPS (aws:SecureTransport: false).",
    "Resource Type": "aws_s3_bucket_policy",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html"
}

#
# PR-AWS-TRF-S3-013
#

default s3_website = null

aws_issue["s3_website"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket"
    resource.properties.website
}

source_path[{"s3_website": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket"
    resource.properties.website

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "website"]
        ],
    }
}

s3_website {
    lower(input.resources[i].type) == "aws_s3_bucket"
    not aws_issue["s3_website"]
}

s3_website = false {
    aws_issue["s3_website"]
}

s3_website_err = "S3 buckets with configurations set to host websites" {
    aws_issue["s3_website"]
}

s3_website_metadata := {
    "Policy Code": "PR-AWS-TRF-S3-013",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "S3 buckets with configurations set to host websites",
    "Policy Description": "To host a website on AWS S3 you should configure a bucket as a website. This policy identifies all the S3 buckets that are configured to host websites. By frequently surveying these S3 buckets you can ensure that only authorized buckets are enabled to host websites. Make sure to disable static website hosting for unauthorized S3 buckets.",
    "Resource Type": "aws_s3_bucket_policy",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html"
}

#
# PR-AWS-TRF-S3-006
#

default s3_cloudtrail = null

aws_issue["s3_cloudtrail"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudtrail"
    lower(resource.properties.enable_logging) == "false"
}

source_path[{"s3_cloudtrail": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudtrail"
    lower(resource.properties.enable_logging) == "false"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "enable_logging"]
        ],
    }
}

aws_bool_issue["s3_cloudtrail"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudtrail"
    not resource.properties.enable_logging
}

source_path[{"s3_cloudtrail": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudtrail"
    not resource.properties.enable_logging

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "enable_logging"]
        ],
    }
}

s3_cloudtrail {
    lower(input.resources[i].type) == "aws_cloudtrail"
    not aws_issue["s3_cloudtrail"]
    not aws_bool_issue["s3_cloudtrail"]
}

s3_cloudtrail = false {
    aws_issue["s3_cloudtrail"]
}

s3_cloudtrail = false {
    aws_bool_issue["s3_cloudtrail"]
}

s3_cloudtrail_err = "AWS S3 CloudTrail buckets for which access logging is disabled" {
    aws_issue["s3_cloudtrail"]
} else = "AWS S3 CloudTrail buckets for which access logging is disabled" {
    aws_bool_issue["s3_cloudtrail"]
}

s3_cloudtrail_metadata := {
    "Policy Code": "PR-AWS-TRF-S3-006",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS S3 CloudTrail buckets for which access logging is disabled",
    "Policy Description": "This policy identifies S3 CloudTrail buckets for which access is disabled.S3 Bucket access logging generates access records for each request made to your S3 bucket. An access log record contains information such as the request type, the resources specified in the request worked, and the time and date the request was processed. It is recommended that bucket access logging be enabled on the CloudTrail S3 bucket",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html"
}

#
# PR-AWS-TRF-S3-008
#

default s3_public_acl = null

aws_issue["s3_public_acl"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket"
    resource.properties.acl == "public-read"
}

source_path[{"s3_public_acl": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket"
    resource.properties.acl == "public-read"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "acl"]
        ],
    }
}

s3_public_acl {
    lower(input.resources[i].type) == "aws_s3_bucket"
    not aws_issue["s3_public_acl"]
}

s3_public_acl = false {
    aws_issue["s3_public_acl"]
}

s3_public_acl_err = "AWS S3 bucket has global view ACL permissions enabled." {
    aws_issue["s3_public_acl"]
}

s3_public_acl_metadata := {
    "Policy Code": "PR-AWS-TRF-S3-008",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS S3 bucket has global view ACL permissions enabled.",
    "Policy Description": "This policy determines if any S3 bucket(s) has Global View ACL permissions enabled for the All Users group. These permissions allow external resources to see the permission settings associated to the object.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html"
}

#
# PR-AWS-TRF-S3-010
#

default s3_auth_acl = null

aws_issue["s3_auth_acl"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket"
    resource.properties.acl == "authenticated-read"
}

source_path[{"s3_auth_acl": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket"
    resource.properties.acl == "authenticated-read"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "acl"]
        ],
    }
}

s3_auth_acl {
    lower(input.resources[i].type) == "aws_s3_bucket"
    not aws_issue["s3_auth_acl"]
}

s3_auth_acl = false {
    aws_issue["s3_auth_acl"]
}

s3_auth_acl_err = "AWS S3 buckets are accessible to any authenticated user." {
    aws_issue["s3_auth_acl"]
}

s3_auth_acl_metadata := {
    "Policy Code": "PR-AWS-TRF-S3-010",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS S3 buckets are accessible to any authenticated user.",
    "Policy Description": "This policy identifies S3 buckets accessible to any authenticated AWS users. Amazon S3 allows customer to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example to host website content. However, these buckets often contain highly sensitive enterprise data which if left accessible to anyone with valid AWS credentials, may result in sensitive data leaks.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html"
}

#
# PR-AWS-TRF-S3-011
#

default s3_public_access = null

aws_issue["s3_public_access"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket"
    resource.properties.acl == "public-read-write"
}

source_path[{"s3_public_access": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket"
    resource.properties.acl == "public-read-write"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "acl"]
        ],
    }
}

s3_public_access {
    lower(input.resources[i].type) == "aws_s3_bucket"
    not aws_issue["s3_public_access"]
}

s3_public_access = false {
    aws_issue["s3_public_access"]
}

s3_public_access_err = "AWS S3 buckets are accessible to public" {
    aws_issue["s3_public_access"]
}

s3_public_access_metadata := {
    "Policy Code": "PR-AWS-TRF-S3-011",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS S3 buckets are accessible to public",
    "Policy Description": "This policy identifies S3 buckets which are publicly accessible. Amazon S3 allows customers to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example, to host website content. However, these buckets often contain highly sensitive enterprise data which if left open to public may result in sensitive data leaks.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html"
}

#
# PR-AWS-TRF-S3-012
#

default s3_encryption = null

aws_issue["s3_encryption"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket"
    not resource.properties.server_side_encryption_configuration
}

source_path[{"s3_encryption": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket"
    not resource.properties.server_side_encryption_configuration

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "server_side_encryption_configuration"]
        ],
    }
}

s3_encryption {
    lower(input.resources[i].type) == "aws_s3_bucket"
    not aws_issue["s3_encryption"]
}

s3_encryption = false {
    aws_issue["s3_encryption"]
}

s3_encryption_err = "AWS S3 buckets do not have server side encryption" {
    aws_issue["s3_encryption"]
}

s3_encryption_metadata := {
    "Policy Code": "PR-AWS-TRF-S3-012",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS S3 buckets do not have server side encryption.",
    "Policy Description": "Customers can protect the data in S3 buckets using the AWS server-side encryption. If the server-side encryption is not turned on for S3 buckets with sensitive data, in the event of a data breach, malicious users can gain access to the data.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html"
}

#
# PR-AWS-TRF-S3-014
#

default s3_cors = null

aws_issue["s3_cors"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket"
    cors_rule := resource.properties.cors_rule[j]
    cors_rule.allowed_headers[k] == "*"
    cors_rule.allowed_methods[l] == "*"
}

source_path[{"s3_cors": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_s3_bucket"
    cors_rule := resource.properties.cors_rule[j]
    cors_rule.allowed_headers[k] == "*"
    cors_rule.allowed_methods[l] == "*"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "cors_rule", j, "allowed_headers", k],
            ["resources", i, "properties", "cors_rule", j, "allowed_methods", l]
        ],
    }
}

s3_cors {
    lower(input.resources[i].type) == "aws_s3_bucket"
    not aws_issue["s3_cors"]
}

s3_cors = false {
    aws_issue["s3_cors"]
}

s3_cors_err = "Ensure S3 hosted sites supported hardened CORS" {
    aws_issue["s3_cors"]
}

s3_cors_metadata := {
    "Policy Code": "PR-AWS-TRF-S3-014",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure S3 hosted sites supported hardened CORS",
    "Policy Description": "Ensure that AllowedOrigins, AllowedMethods should not be set to *. this allows all cross site users to access s3 bucket and they have permission to manipulate data",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html#aws-properties-s3-bucket--seealso"
}