package rule
default metadata = {}

has_property(parent_object, target_property) { 
	_ = parent_object[target_property]
}


# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html
# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-policy.html

#
# PR-AWS-CFR-S3-001
#

default s3_accesslog = null

aws_attribute_absence["s3_accesslog"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    not resource.Properties.LoggingConfiguration.DestinationBucketName
}

source_path[{"s3_accesslog": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    not resource.Properties.LoggingConfiguration.DestinationBucketName
    metadata := {
        "resource_path": [["Resources", i, "Properties", "LoggingConfiguration", "DestinationBucketName"]],
    }
}

aws_attribute_absence["s3_accesslog"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    not resource.Properties.LoggingConfiguration.LogFilePrefix
}

source_path[{"s3_accesslog": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    not resource.Properties.LoggingConfiguration.LogFilePrefix
    metadata := {
        "resource_path": [["Resources", i, "Properties", "LoggingConfiguration", "LogFilePrefix"]],
    }
}

aws_issue["s3_accesslog"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    count(resource.Properties.LoggingConfiguration.DestinationBucketName) == 0
}

source_path[{"s3_accesslog": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    count(resource.Properties.LoggingConfiguration.DestinationBucketName) == 0
    metadata := {
        "resource_path": [["Resources", i, "Properties", "LoggingConfiguration", "DestinationBucketName"]],
    }
}

aws_issue["s3_accesslog"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    count(resource.Properties.LoggingConfiguration.LogFilePrefix) == 0
}

source_path[{"s3_accesslog": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    count(resource.Properties.LoggingConfiguration.LogFilePrefix) == 0
    metadata := {
        "resource_path": [["Resources", i, "Properties", "LoggingConfiguration", "LogFilePrefix"]],
    }
}

s3_accesslog {
    lower(input.Resources[i].Type) == "aws::s3::bucket"
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
}

s3_accesslog_miss_err = "S3 Bucket attribute DestinationBucketName/LogFilePrefix missing in the resource" {
    aws_attribute_absence["s3_accesslog"]
}

s3_accesslog_metadata := {
    "Policy Code": "PR-AWS-CFR-S3-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Access logging not enabled on S3 buckets",
    "Policy Description": "Checks for S3 buckets without access logging turned on. Access logging allows customers to view complete audit trail on sensitive workloads such as S3 buckets",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html"
}


#
# PR-AWS-CFR-S3-002
#

default s3_acl_delete = null

aws_attribute_absence["s3_acl_delete"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    not resource.Properties.PolicyDocument.Statement
}

aws_issue["s3_acl_delete"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    stat := resource.Properties.PolicyDocument.Statement[_]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    lower(stat.Action[_]) == "s3:*"
}

aws_issue["s3_acl_delete"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    stat := resource.Properties.PolicyDocument.Statement[_]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    startswith(lower(stat.Action),"s3:delete")
}

aws_issue["s3_acl_delete"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    stat := resource.Properties.PolicyDocument.Statement[_]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    startswith(lower(stat.Action[_]),"s3:delete")
}

source_path[{"s3_acl_delete": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    not resource.Properties.PolicyDocument.Statement
    metadata := {
        "resource_path": [["Resources", i, "Properties", "PolicyDocument", "Statement"]],
    }
}

source_path[{"s3_acl_delete": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    stat := resource.Properties.PolicyDocument.Statement[j]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    lower(stat.Action[k]) == "s3:*"
    metadata := {
        "resource_path": [["Resources", i, "Properties", "PolicyDocument", "Statement", j, "Action", k]],
    }
}

source_path[{"s3_acl_delete": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    stat := resource.Properties.PolicyDocument.Statement[j]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    startswith(lower(stat.Action),"s3:delete")
    metadata := {
        "resource_path": [["Resources", i, "Properties", "PolicyDocument", "Statement", j, "Action"]],
    }
}

source_path[{"s3_acl_delete": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    stat := resource.Properties.PolicyDocument.Statement[j]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    startswith(lower(stat.Action[k]),"s3:delete")
    metadata := {
        "resource_path": [["Resources", i, "Properties", "PolicyDocument", "Statement", j, "Action", k]],
    }
}


s3_acl_delete {
    lower(input.Resources[i].Type) == "aws::s3::bucketpolicy"
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
}

s3_acl_delete_miss_err = "S3 Policy attribute PolicyDocument.Statement missing in the resource" {
    aws_attribute_absence["s3_acl_delete"]
}

s3_acl_delete_metadata := {
    "Policy Code": "PR-AWS-CFR-S3-002",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS S3 Bucket has Global DELETE Permissions enabled via bucket policy",
    "Policy Description": "This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to DELETE objects from a bucket. These permissions permit anyone, malicious or not, to DELETE objects from your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk loss or compromise of critical data by leaving this open.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html"
}

#
# PR-AWS-CFR-S3-003
#

default s3_acl_get = null

aws_attribute_absence["s3_acl_get"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    not resource.Properties.PolicyDocument.Statement
}

aws_issue["s3_acl_get"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    stat := resource.Properties.PolicyDocument.Statement[_]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    lower(stat.Action[_]) == "s3:*"
}

aws_issue["s3_acl_get"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    stat := resource.Properties.PolicyDocument.Statement[_]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    startswith(lower(stat.Action),"s3:get")
}

aws_issue["s3_acl_get"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    stat := resource.Properties.PolicyDocument.Statement[_]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    startswith(lower(stat.Action[_]),"s3:get")
}


source_path[{"s3_acl_get": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    not resource.Properties.PolicyDocument.Statement
    metadata := {
        "resource_path": [["Resources", i, "Properties", "PolicyDocument", "Statement"]],
    }
}

source_path[{"s3_acl_get": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    stat := resource.Properties.PolicyDocument.Statement[j]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    lower(stat.Action[k]) == "s3:*"
    metadata := {
        "resource_path": [["Resources", i, "Properties", "PolicyDocument", "Statement", j, "Action", k]],
    }
}

source_path[{"s3_acl_get": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    stat := resource.Properties.PolicyDocument.Statement[j]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    startswith(lower(stat.Action),"s3:get")
    metadata := {
        "resource_path": [["Resources", i, "Properties", "PolicyDocument", "Statement", j, "Action"]],
    }
}

source_path[{"s3_acl_get": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    stat := resource.Properties.PolicyDocument.Statement[j]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    startswith(lower(stat.Action[k]),"s3:get")
    metadata := {
        "resource_path": [["Resources", i, "Properties", "PolicyDocument", "Statement", j, "Action", k]],
    }
}

s3_acl_get {
    lower(input.Resources[i].Type) == "aws::s3::bucketpolicy"
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
}

s3_acl_get_miss_err = "S3 Policy attribute PolicyDocument.Statement missing in the resource" {
    aws_attribute_absence["s3_acl_get"]
}

s3_acl_get_metadata := {
    "Policy Code": "PR-AWS-CFR-S3-003",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS S3 Bucket has Global GET Permissions enabled via bucket policy",
    "Policy Description": "This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to GET objects from a bucket. These permissions permit anyone, malicious or not, to GET objects from your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk loss or compromise of critical data by leaving this open.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html"
}

#
# PR-AWS-CFR-S3-004
#

default s3_acl_list = null

aws_attribute_absence["s3_acl_list"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    not resource.Properties.PolicyDocument.Statement
}

aws_issue["s3_acl_list"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    stat := resource.Properties.PolicyDocument.Statement[_]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    lower(stat.Action[_]) == "s3:*"
}

aws_issue["s3_acl_list"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    stat := resource.Properties.PolicyDocument.Statement[_]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    startswith(lower(stat.Action),"s3:list")

}

aws_issue["s3_acl_list"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    stat := resource.Properties.PolicyDocument.Statement[_]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    startswith(lower(stat.Action[_]),"s3:list")

}

source_path[{"s3_acl_list": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    not resource.Properties.PolicyDocument.Statement
    metadata := {
        "resource_path": [["Resources", i, "Properties", "PolicyDocument", "Statement"]],
    }
}

source_path[{"s3_acl_list": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    stat := resource.Properties.PolicyDocument.Statement[j]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    lower(stat.Action[k]) == "s3:*"
    metadata := {
        "resource_path": [["Resources", i, "Properties", "PolicyDocument", "Statement", j, "Action", k]],
    }
}

source_path[{"s3_acl_list": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    stat := resource.Properties.PolicyDocument.Statement[j]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    startswith(lower(stat.Action),"s3:list")
    metadata := {
        "resource_path": [["Resources", i, "Properties", "PolicyDocument", "Statement", j, "Action"]],
    }

}

source_path[{"s3_acl_list": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    stat := resource.Properties.PolicyDocument.Statement[j]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    startswith(lower(stat.Action[k]),"s3:list")
    metadata := {
        "resource_path": [["Resources", i, "Properties", "PolicyDocument", "Statement", j, "Action", k]],
    }

}

s3_acl_list {
    lower(input.Resources[i].Type) == "aws::s3::bucketpolicy"
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
}

s3_acl_list_miss_err = "S3 Policy attribute PolicyDocument.Statement missing in the resource" {
    aws_attribute_absence["s3_acl_list"]
}

s3_acl_list_metadata := {
    "Policy Code": "PR-AWS-CFR-S3-004",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS S3 Bucket has Global LIST Permissions enabled via bucket policy",
    "Policy Description": "This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to LIST objects from a bucket. These permissions permit anyone, malicious or not, to LIST objects from your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk loss or compromise of critical data by leaving this open.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html"
}

#
# PR-AWS-CFR-S3-005
#

default s3_acl_put = null

aws_attribute_absence["s3_acl_put"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    not resource.Properties.PolicyDocument.Statement
}

aws_issue["s3_acl_put"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    stat := resource.Properties.PolicyDocument.Statement[_]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    lower(stat.Action[_]) == "s3:*"
}

aws_issue["s3_acl_put"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    stat := resource.Properties.PolicyDocument.Statement[_]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    startswith(lower(stat.Action),"s3:put")

}

aws_issue["s3_acl_put"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    stat := resource.Properties.PolicyDocument.Statement[_]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    startswith(lower(stat.Action[_]),"s3:put")
}

source_path[{"s3_acl_put": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    not resource.Properties.PolicyDocument.Statement
    metadata := {
        "resource_path": [["Resources", i, "Properties", "PolicyDocument", "Statement"]],
    }
}

source_path[{"s3_acl_put": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    stat := resource.Properties.PolicyDocument.Statement[j]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    lower(stat.Action[k]) == "s3:*"
    metadata := {
        "resource_path": [["Resources", i, "Properties", "PolicyDocument", "Statement", j, "Action", k]],
    }
}

source_path[{"s3_acl_put": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    stat := resource.Properties.PolicyDocument.Statement[j]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    startswith(lower(stat.Action),"s3:put")
    metadata := {
        "resource_path": [["Resources", i, "Properties", "PolicyDocument", "Statement", j, "Action"]],
    }

}

source_path[{"s3_acl_put": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    stat := resource.Properties.PolicyDocument.Statement[j]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    startswith(lower(stat.Action[k]),"s3:put")
    metadata := {
        "resource_path": [["Resources", i, "Properties", "PolicyDocument", "Statement", j, "Action", k]],
    }
}

s3_acl_put {
    lower(input.Resources[i].Type) == "aws::s3::bucketpolicy"
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
}

s3_acl_put_miss_err = "S3 Policy attribute PolicyDocument.Statement missing in the resource" {
    aws_attribute_absence["s3_acl_put"]
}

s3_acl_put_metadata := {
    "Policy Code": "PR-AWS-CFR-S3-005",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS S3 Bucket has Global PUT Permissions enabled via bucket policy",
    "Policy Description": "This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to PUT objects into a bucket. These permissions permit anyone, malicious or not, to PUT objects into your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk compromise of critical data by leaving this open.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html"
}

#
# PR-AWS-CFR-S3-006
#

default s3_cloudtrail = null

aws_issue["s3_cloudtrail"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudtrail::trail"
    lower(resource.Properties.IsLogging) == "false"
}

aws_bool_issue["s3_cloudtrail"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudtrail::trail"
    not resource.Properties.IsLogging
}

source_path[{"s3_cloudtrail": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudtrail::trail"
    lower(resource.Properties.IsLogging) == "false"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "IsLogging"],
        ],
    }
}

source_path[{"s3_cloudtrail": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudtrail::trail"
    not resource.Properties.IsLogging
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "IsLogging"],
        ],
    }
}

s3_cloudtrail {
    lower(input.Resources[i].Type) == "aws::cloudtrail::trail"
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
    "Policy Code": "PR-AWS-CFR-S3-006",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS S3 CloudTrail buckets for which access logging is disabled",
    "Policy Description": "This policy identifies S3 CloudTrail buckets for which access is disabled.S3 Bucket access logging generates access records for each request made to your S3 bucket. An access log record contains information such as the request type, the resources specified in the request worked, and the time and date the request was processed. It is recommended that bucket access logging be enabled on the CloudTrail S3 bucket",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html"
}

#
# PR-AWS-CFR-S3-007
#

default s3_versioning = null

aws_attribute_absence["s3_versioning"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    not resource.Properties.VersioningConfiguration.Status
}

aws_issue["s3_versioning"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    lower(resource.Properties.VersioningConfiguration.Status) != "enabled"
}

source_path[{"s3_versioning": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    not resource.Properties.VersioningConfiguration.Status
    metadata := {
        "resource_path": [["Resources", i, "Properties", "VersioningConfiguration", "Status"]],
    }
}

source_path[{"s3_versioning": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    lower(resource.Properties.VersioningConfiguration.Status) != "enabled"
    metadata := {
        "resource_path": [["Resources", i, "Properties", "VersioningConfiguration", "Status"]],
    }
}

s3_versioning {
    lower(input.Resources[i].Type) == "aws::s3::bucket"
    not aws_issue["s3_versioning"]
    not aws_attribute_absence["s3_versioning"]
}

s3_versioning = false {
    aws_issue["s3_versioning"]
}

s3_versioning = false {
    aws_attribute_absence["s3_versioning"]
}

s3_versioning_err = "AWS S3 Object Versioning is disabled" {
    aws_issue["s3_versioning"]
}

s3_versioning_miss_err = "S3 Bucket attribute VersioningConfiguration.Status missing in the resource" {
    aws_attribute_absence["s3_versioning"]
}

s3_versioning_metadata := {
    "Policy Code": "PR-AWS-CFR-S3-007",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS S3 Object Versioning is disabled",
    "Policy Description": "This policy identifies the S3 buckets which have Object Versioning disabled. S3 Object Versioning is an important capability in protecting your data within a bucket. Once you enable Object Versioning, you cannot remove it; you can suspend Object Versioning at any time on a bucket if you do not wish for it to persist. It is recommended to enable Object Versioning on S3.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html"
}

#
# PR-AWS-CFR-S3-008
#

default s3_public_acl = null

aws_issue["s3_public_acl"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    resource.Properties.AccessControl == "PublicRead"
}

source_path[{"s3_public_acl": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    lower(resource.Properties.AccessControl) == "publicread"
    metadata := {
        "resource_path": [["Resources", i, "Properties", "AccessControl"]],
    }
}

s3_public_acl {
    lower(input.Resources[i].Type) == "aws::s3::bucket"
    not aws_issue["s3_public_acl"]
}

s3_public_acl = false {
    aws_issue["s3_public_acl"]
}

s3_public_acl_err = "AWS S3 bucket has global view ACL permissions enabled." {
    aws_issue["s3_public_acl"]
}

s3_public_acl_metadata := {
    "Policy Code": "PR-AWS-CFR-S3-008",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS S3 bucket has global view ACL permissions enabled.",
    "Policy Description": "This policy determines if any S3 bucket(s) has Global View ACL permissions enabled for the All Users group. These permissions allow external resources to see the permission settings associated to the object.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html"
}

#
# PR-AWS-CFR-S3-009
#

default s3_transport = null

aws_issue["s3_transport"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    statement := resource.Properties.PolicyDocument.Statement[_]
    not statement.Condition.StringLike
    not statement.Condition.Bool
}

aws_issue["s3_transport"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    statement := resource.Properties.PolicyDocument.Statement[_]
    statement.Condition.StringLike
    lower(statement.Condition.StringLike["aws:SecureTransport"]) != "true"
}

aws_issue["s3_transport"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    statement := resource.Properties.PolicyDocument.Statement[_]
    statement.Condition.Bool
    lower(statement.Condition.Bool["aws:SecureTransport"]) != "true"
}

aws_bool_issue["s3_transport"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    statement := resource.Properties.PolicyDocument.Statement[_]
    statement.Condition.StringLike
    not statement.Condition.StringLike["aws:SecureTransport"]
}

aws_bool_issue["s3_transport"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    statement := resource.Properties.PolicyDocument.Statement[_]
    statement.Condition.Bool
    not statement.Condition.Bool["aws:SecureTransport"]
}

source_path[{"s3_transport": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    statement := resource.Properties.PolicyDocument.Statement[j]
    not statement.Condition.StringLike
    not statement.Condition.Bool
    
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "PolicyDocument", "Statement", j, "StringLike"],
            ["Resources", i, "Properties", "PolicyDocument", "Statement", j, "Bool"]
        ],
    }
}

source_path[{"s3_transport": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    statement := resource.Properties.PolicyDocument.Statement[j]
    statement.Condition.StringLike
    lower(statement.Condition.StringLike["aws:SecureTransport"]) != "true"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "PolicyDocument", "Statement", j, "StringLike", "aws:SecureTransport"],
        ],
    }
}

source_path[{"s3_transport": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    statement := resource.Properties.PolicyDocument.Statement[j]
    statement.Condition.Bool
    lower(statement.Condition.Bool["aws:SecureTransport"]) != "true"
     metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "PolicyDocument", "Statement", j, "Bool", "aws:SecureTransport"],
        ],
    }
}

source_path[{"s3_transport": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    statement := resource.Properties.PolicyDocument.Statement[j]
    statement.Condition.StringLike
    not statement.Condition.StringLike["aws:SecureTransport"]
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "PolicyDocument", "Statement", j, "StringLike", "aws:SecureTransport"],
        ],
    }
}

source_path[{"s3_transport": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    statement := resource.Properties.PolicyDocument.Statement[j]
    statement.Condition.Bool
    not statement.Condition.Bool["aws:SecureTransport"]
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "PolicyDocument", "Statement", j, "Bool", "aws:SecureTransport"],
        ],
    }
}

s3_transport {
    lower(input.Resources[i].Type) == "aws::s3::bucketpolicy"
    not aws_issue["s3_transport"]
    not aws_bool_issue["s3_transport"]
}

s3_transport = false {
    aws_issue["s3_transport"]
}

s3_transport = false {
    aws_bool_issue["s3_transport"]
}


s3_transport_err = "AWS S3 bucket not configured with secure data transport policy" {
    aws_issue["s3_transport"]
} else = "AWS S3 bucket not configured with secure data transport policy" {
    aws_bool_issue["s3_transport"]
}

s3_transport_metadata := {
    "Policy Code": "PR-AWS-CFR-S3-009",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS S3 bucket not configured with secure data transport policy",
    "Policy Description": "This policy identifies S3 buckets which are not configured with secure data transport policy. AWS S3 buckets should enforce encryption of data over the network using Secure Sockets Layer (SSL). It is recommended to add a bucket policy that explicitly denies (Effect: Deny) all access (Action: s3:*) from anybody who browses (Principal: *) to Amazon S3 objects within an Amazon S3 bucket if they are not accessed through HTTPS (aws:SecureTransport: false).",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html"
}

#
# PR-AWS-CFR-S3-010
#

default s3_auth_acl = null

aws_issue["s3_auth_acl"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    resource.Properties.AccessControl == "AuthenticatedRead"
}

source_path[{"s3_auth_acl": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    lower(resource.Properties.AccessControl) == "authenticatedread"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "AccessControl"],
        ],
    }
}

s3_auth_acl {
    lower(input.Resources[i].Type) == "aws::s3::bucket"
    not aws_issue["s3_auth_acl"]
}

s3_auth_acl = false {
    aws_issue["s3_auth_acl"]
}

s3_auth_acl_err = "AWS S3 buckets are accessible to any authenticated user." {
    aws_issue["s3_auth_acl"]
}

s3_auth_acl_metadata := {
    "Policy Code": "PR-AWS-CFR-S3-010",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS S3 buckets are accessible to any authenticated user.",
    "Policy Description": "This policy identifies S3 buckets accessible to any authenticated AWS users. Amazon S3 allows customer to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example to host website content. However, these buckets often contain highly sensitive enterprise data which if left accessible to anyone with valid AWS credentials, may result in sensitive data leaks.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html"
}

#
# PR-AWS-CFR-S3-011
#

default s3_public_access = null

aws_issue["s3_public_access"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    resource.Properties.AccessControl == "PublicRead"
}

aws_issue["s3_public_access"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    resource.Properties.AccessControl == "PublicReadWrite"
}

source_path[{"s3_public_access": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    lower(resource.Properties.AccessControl) == "publicread"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "AccessControl"],
        ],
    }
}

source_path[{"s3_public_access": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    lower(resource.Properties.AccessControl) == "publicreadwrite"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "AccessControl"],
        ],
    }
}

s3_public_access {
    lower(input.Resources[i].Type) == "aws::s3::bucket"
    not aws_issue["s3_public_access"]
}

s3_public_access = false {
    aws_issue["s3_public_access"]
}

s3_public_access_err = "AWS S3 buckets are accessible to public" {
    aws_issue["s3_public_access"]
}

s3_public_access_metadata := {
    "Policy Code": "PR-AWS-CFR-S3-011",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS S3 buckets are accessible to public",
    "Policy Description": "This policy identifies S3 buckets which are publicly accessible. Amazon S3 allows customers to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example, to host website content. However, these buckets often contain highly sensitive enterprise data which if left open to public may result in sensitive data leaks.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html"
}

#
# PR-AWS-CFR-S3-012
#

default s3_encryption = null

aws_issue["s3_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    not resource.Properties.BucketEncryption.ServerSideEncryptionConfiguration
}

source_path["s3_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "BucketEncryption", "ServerSideEncryptionConfiguration"],
        ],
    }
}

s3_encryption {
    lower(input.Resources[i].Type) == "aws::s3::bucket"
    not aws_issue["s3_encryption"]
}

s3_encryption = false {
    aws_issue["s3_encryption"]
}

s3_encryption_err = "AWS S3 buckets do not have server side encryption" {
    aws_issue["s3_encryption"]
}

s3_encryption_metadata := {
    "Policy Code": "PR-AWS-CFR-S3-012",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS S3 buckets do not have server side encryption.",
    "Policy Description": "Customers can protect the data in S3 buckets using the AWS server-side encryption. If the server-side encryption is not turned on for S3 buckets with sensitive data, in the event of a data breach, malicious users can gain access to the data.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html"
}

#
# PR-AWS-CFR-S3-013
#

default s3_website = null

aws_issue["s3_website"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    resource.Properties.WebsiteConfiguration
}

source_path[{"s3_website": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    resource.Properties.WebsiteConfiguration
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "WebsiteConfiguration"],
        ],
    }
}

s3_website {
    lower(input.Resources[i].Type) == "aws::s3::bucket"
    not aws_issue["s3_website"]
}

s3_website = false {
    aws_issue["s3_website"]
}

s3_website_err = "S3 buckets with configurations set to host websites" {
    aws_issue["s3_website"]
}

s3_website_metadata := {
    "Policy Code": "PR-AWS-CFR-S3-013",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "S3 buckets with configurations set to host websites",
    "Policy Description": "To host a website on AWS S3 you should configure a bucket as a website. This policy identifies all the S3 buckets that are configured to host websites. By frequently surveying these S3 buckets you can ensure that only authorized buckets are enabled to host websites. Make sure to disable static website hosting for unauthorized S3 buckets.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html"
}


#
# PR-AWS-CFR-S3-014
#

default s3_cors = null

aws_issue["s3_cors"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    cors_rule := resource.Properties.CorsConfiguration.CorsRules[_]
    cors_rule.AllowedHeaders[_] == "*"
    cors_rule.AllowedMethods[_] == "*"
}

source_path[{"s3_cors": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    cors_rule := resource.Properties.CorsConfiguration.CorsRules[j]
    cors_rule.AllowedHeaders[k] == "*"
    cors_rule.AllowedMethods[l] == "*"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "CorsConfiguration", "CorsRules", j, "AllowedHeaders", k],
            ["Resources", i, "Properties", "CorsConfiguration", "CorsRules", j, "AllowedHeaders", l]
        ],
    }
}

s3_cors {
    lower(input.Resources[i].Type) == "aws::s3::bucket"
    not aws_issue["s3_cors"]
}

s3_cors = false {
    aws_issue["s3_cors"]
}

s3_cors_err = "Ensure S3 hosted sites supported hardened CORS" {
    aws_issue["s3_cors"]
}

s3_cors_metadata := {
    "Policy Code": "PR-AWS-CFR-S3-014",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure S3 hosted sites supported hardened CORS",
    "Policy Description": "Ensure that AllowedOrigins, AllowedMethods should not be set to *. this allows all cross site users to access s3 bucket and they have permission to manipulate data",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html#aws-properties-s3-bucket--seealso"
}


#
# PR-AWS-CFR-S3-015
#

default bucket_kms_encryption = null


aws_issue["bucket_kms_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    count(resource.Properties.BucketEncryption.ServerSideEncryptionConfiguration) == 0
}

source_path[{"bucket_kms_encryption": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    count(resource.Properties.BucketEncryption.ServerSideEncryptionConfiguration) == 0
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "BucketEncryption", "ServerSideEncryptionConfiguration"]
        ],
    }
}

aws_issue["bucket_kms_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    not resource.Properties.BucketEncryption.ServerSideEncryptionConfiguration
}

source_path[{"bucket_kms_encryption": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    not resource.Properties.BucketEncryption.ServerSideEncryptionConfiguration
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "BucketEncryption", "ServerSideEncryptionConfiguration"]
        ],
    }
}

aws_issue["bucket_kms_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    ServerSideEncryptionConfiguration := resource.Properties.BucketEncryption.ServerSideEncryptionConfiguration[j]
    not ServerSideEncryptionConfiguration.BucketKeyEnabled
}

source_path[{"bucket_kms_encryption": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    ServerSideEncryptionConfiguration := resource.Properties.BucketEncryption.ServerSideEncryptionConfiguration[j]
    not ServerSideEncryptionConfiguration.BucketKeyEnabled
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "BucketEncryption", "ServerSideEncryptionConfiguration", j, "ServerSideEncryptionConfiguration", "ServerSideEncryptionConfiguration"]
        ],
    }
}

aws_issue["bucket_kms_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    ServerSideEncryptionConfiguration := resource.Properties.BucketEncryption.ServerSideEncryptionConfiguration[j]
    lower(ServerSideEncryptionConfiguration.BucketKeyEnabled) == "false"
}

source_path[{"bucket_kms_encryption": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    ServerSideEncryptionConfiguration := resource.Properties.BucketEncryption.ServerSideEncryptionConfiguration[j]
    lower(ServerSideEncryptionConfiguration.BucketKeyEnabled) == "false"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "BucketEncryption", "ServerSideEncryptionConfiguration", j, "ServerSideEncryptionConfiguration", "ServerSideEncryptionConfiguration"]
        ],
    }
}

aws_issue["bucket_kms_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    ServerSideEncryptionConfiguration := resource.Properties.BucketEncryption.ServerSideEncryptionConfiguration[j]
    lower(ServerSideEncryptionConfiguration.ServerSideEncryptionByDefault.SSEAlgorithm) != "aws:kms"
}

source_path[{"bucket_kms_encryption": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    ServerSideEncryptionConfiguration := resource.Properties.BucketEncryption.ServerSideEncryptionConfiguration[j]
    lower(ServerSideEncryptionConfiguration.ServerSideEncryptionByDefault.SSEAlgorithm) != "aws:kms"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "BucketEncryption", "ServerSideEncryptionConfiguration", j, "ServerSideEncryptionByDefault", "SSEAlgorithm"]
        ],
    }
}

aws_issue["bucket_kms_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    ServerSideEncryptionConfiguration := resource.Properties.BucketEncryption.ServerSideEncryptionConfiguration[j]
    lower(ServerSideEncryptionConfiguration.ServerSideEncryptionByDefault.SSEAlgorithm) == "aws:kms"
    not ServerSideEncryptionConfiguration.ServerSideEncryptionByDefault.KMSMasterKeyID
}

source_path[{"bucket_kms_encryption": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    ServerSideEncryptionConfiguration := resource.Properties.BucketEncryption.ServerSideEncryptionConfiguration[j]
    lower(ServerSideEncryptionConfiguration.ServerSideEncryptionByDefault.SSEAlgorithm) == "aws:kms"
    not ServerSideEncryptionConfiguration.ServerSideEncryptionByDefault.KMSMasterKeyID
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "BucketEncryption", "ServerSideEncryptionConfiguration", j, "ServerSideEncryptionByDefault", "KMSMasterKeyID"]
        ],
    }
}

aws_issue["bucket_kms_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    ServerSideEncryptionConfiguration := resource.Properties.BucketEncryption.ServerSideEncryptionConfiguration[j]
    lower(ServerSideEncryptionConfiguration.ServerSideEncryptionByDefault.SSEAlgorithm) == "aws:kms"
    count(ServerSideEncryptionConfiguration.ServerSideEncryptionByDefault.KMSMasterKeyID) == 0
}

source_path[{"bucket_kms_encryption": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    ServerSideEncryptionConfiguration := resource.Properties.BucketEncryption.ServerSideEncryptionConfiguration[j]
    lower(ServerSideEncryptionConfiguration.ServerSideEncryptionByDefault.SSEAlgorithm) == "aws:kms"
    count(ServerSideEncryptionConfiguration.ServerSideEncryptionByDefault.KMSMasterKeyID) == 0
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "BucketEncryption", "ServerSideEncryptionConfiguration", j, "ServerSideEncryptionByDefault", "KMSMasterKeyID"]
        ],
    }
}


bucket_kms_encryption {
    lower(input.Resources[i].Type) == "aws::s3::bucket"
    not aws_issue["bucket_kms_encryption"]
}

bucket_kms_encryption = false {
    aws_issue["bucket_kms_encryption"]
}


bucket_kms_encryption_err = "Ensure S3 bucket is encrypted using KMS" {
    aws_issue["bucket_kms_encryption"]
}

bucket_kms_encryption_metadata := {
    "Policy Code": "PR-AWS-CFR-S3-015",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure S3 bucket is encrypted using KMS",
    "Policy Description": "Ensure that your AWS S3 buckets are configured to use Server-Side Encryption with customer managed CMKs instead of S3-Managed Keys (SSE-S3) in order to obtain a fine-grained control over Amazon S3 data-at-rest encryption and decryption process",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-serversideencryptionbydefault.html#cfn-s3-bucket-serversideencryptionbydefault-ssealgorithm"
}


#
# PR-AWS-CFR-S3-016
#

default s3_object_lock_enable = null

aws_issue["s3_object_lock_enable"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    not resource.Properties.ObjectLockEnabled
}

source_path[{"s3_object_lock_enable": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    not resource.Properties.ObjectLockEnabled
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "ObjectLockEnabled"]
        ],
    }
}

aws_issue["s3_object_lock_enable"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    lower(resource.Properties.ObjectLockEnabled) != "true"
}

source_path[{"s3_object_lock_enable": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    lower(resource.Properties.ObjectLockEnabled) != "true"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "ObjectLockEnabled"]
        ],
    }
}

s3_object_lock_enable {
    lower(input.Resources[i].Type) == "aws::s3::bucket"
    not aws_issue["s3_object_lock_enable"]
}

s3_object_lock_enable = false {
    aws_issue["s3_object_lock_enable"]
}

s3_object_lock_enable_err = "Ensure S3 bucket has enabled lock configuration" {
    aws_issue["s3_object_lock_enable"]
}

s3_object_lock_enable_metadata := {
    "Policy Code": "PR-AWS-CFR-S3-016",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure S3 bucket has enabled lock configuration",
    "Policy Description": "Indicates whether this bucket has an Object Lock configuration enabled. Enable ObjectLockEnabled when you apply ObjectLockConfiguration to a bucket.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html#cfn-s3-bucket-objectlockenabled"
}


#
# PR-AWS-CFR-S3-017
#

default s3_cross_region_replica = null

aws_issue["s3_cross_region_replica"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    Rules := resource.Properties.ReplicationConfiguration.Rules[j]
    not Rules.Destination
}

source_path[{"s3_cross_region_replica": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    Rules := resource.Properties.ReplicationConfiguration.Rules[j]
    not Rules.Destination
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "ReplicationConfiguration", "Rules", j, "Destination"]
        ],
    }
}

aws_issue["s3_cross_region_replica"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    not resource.Properties.ReplicationConfiguration
}

source_path[{"s3_cross_region_replica": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    not resource.Properties.ReplicationConfiguration
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "ReplicationConfiguration"]
        ],
    }
}

s3_cross_region_replica {
    lower(input.Resources[i].Type) == "aws::s3::bucket"
    not aws_issue["s3_cross_region_replica"]
}

s3_cross_region_replica = false {
    aws_issue["s3_cross_region_replica"]
}

s3_cross_region_replica_err = "Ensure S3 bucket cross-region replication is enabled" {
    aws_issue["s3_cross_region_replica"]
}

s3_cross_region_replica_metadata := {
    "Policy Code": "PR-AWS-CFR-S3-017",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure S3 bucket cross-region replication is enabled",
    "Policy Description": "Cross-region replication enables automatic, asynchronous copying of objects across S3 buckets. By default, replication supports copying new S3 objects after it is enabled",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-replicationconfiguration-rules.html#cfn-s3-bucket-replicationconfiguration-rules-destination"
}


#
# PR-AWS-CFR-S3-018
#

default s3_public_access_block = null

aws_issue["s3_public_access_block"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    not resource.Properties.PublicAccessBlockConfiguration.BlockPublicAcls
}

source_path[{"s3_public_access_block": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    not resource.Properties.PublicAccessBlockConfiguration.BlockPublicAcls
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "PublicAccessBlockConfiguration", "BlockPublicAcls"]
        ],
    }
}

aws_issue["s3_public_access_block"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    lower(resource.Properties.PublicAccessBlockConfiguration.BlockPublicAcls) != "true"
}

source_path[{"s3_public_access_block": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    lower(resource.Properties.PublicAccessBlockConfiguration.BlockPublicAcls) != "true"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "PublicAccessBlockConfiguration", "BlockPublicAcls"]
        ],
    }
}

s3_public_access_block {
    lower(input.Resources[i].Type) == "aws::s3::bucket"
    not aws_issue["s3_public_access_block"]
}

s3_public_access_block = false {
    aws_issue["s3_public_access_block"]
}

s3_public_access_block_err = "Ensure S3 Bucket has public access blocks" {
    aws_issue["s3_public_access_block"]
}

s3_public_access_block_metadata := {
    "Policy Code": "PR-AWS-CFR-S3-018",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure S3 Bucket has public access blocks",
    "Policy Description": "We recommend you ensure S3 bucket has public access blocks. If the public access block is not attached it defaults to False",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-publicaccessblockconfiguration.html#cfn-s3-bucket-publicaccessblockconfiguration-blockpublicpolicy"
}


#
# PR-AWS-CFR-S3-019
#

default s3_restrict_public_bucket = null

aws_issue["s3_restrict_public_bucket"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    not resource.Properties.PublicAccessBlockConfiguration.RestrictPublicBuckets
}

source_path[{"s3_restrict_public_bucket": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    not resource.Properties.PublicAccessBlockConfiguration.RestrictPublicBuckets
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "PublicAccessBlockConfiguration", "RestrictPublicBuckets"]
        ],
    }
}

aws_issue["s3_restrict_public_bucket"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    lower(resource.Properties.PublicAccessBlockConfiguration.RestrictPublicBuckets) != "true"
}

source_path[{"s3_restrict_public_bucket": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    lower(resource.Properties.PublicAccessBlockConfiguration.RestrictPublicBuckets) != "true"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "PublicAccessBlockConfiguration", "RestrictPublicBuckets"]
        ],
    }
}

s3_restrict_public_bucket {
    lower(input.Resources[i].Type) == "aws::s3::bucket"
    not aws_issue["s3_restrict_public_bucket"]
}

s3_restrict_public_bucket = false {
    aws_issue["s3_restrict_public_bucket"]
}

s3_restrict_public_bucket_err = "Ensure S3 bucket RestrictPublicBucket is enabled" {
    aws_issue["s3_restrict_public_bucket"]
}

s3_restrict_public_bucket_metadata := {
    "Policy Code": "PR-AWS-CFR-S3-019",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure S3 bucket RestrictPublicBucket is enabled",
    "Policy Description": "Enabling this setting does not affect previously stored bucket policies. Public and cross-account access within any public bucket policy, including non-public delegation to specific accounts, is blocked",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-publicaccessblockconfiguration.html#cfn-s3-bucket-publicaccessblockconfiguration-restrictpublicbuckets"
}


#
# PR-AWS-CFR-S3-020
#

default s3_ignore_public_acl = null

aws_issue["s3_ignore_public_acl"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    not resource.Properties.PublicAccessBlockConfiguration.IgnorePublicAcls
}

source_path[{"s3_ignore_public_acl": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    not resource.Properties.PublicAccessBlockConfiguration.IgnorePublicAcls
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "PublicAccessBlockConfiguration", "IgnorePublicAcls"]
        ],
    }
}

aws_issue["s3_ignore_public_acl"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    lower(resource.Properties.PublicAccessBlockConfiguration.IgnorePublicAcls) != "true"
}

source_path[{"s3_ignore_public_acl": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    lower(resource.Properties.PublicAccessBlockConfiguration.IgnorePublicAcls) != "true"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "PublicAccessBlockConfiguration", "IgnorePublicAcls"]
        ],
    }
}

s3_ignore_public_acl {
    lower(input.Resources[i].Type) == "aws::s3::bucket"
    not aws_issue["s3_ignore_public_acl"]
}

s3_ignore_public_acl = false {
    aws_issue["s3_ignore_public_acl"]
}

s3_ignore_public_acl_err = "Ensure S3 bucket IgnorePublicAcls is enabled" {
    aws_issue["s3_ignore_public_acl"]
}

s3_ignore_public_acl_metadata := {
    "Policy Code": "PR-AWS-CFR-S3-020",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure S3 bucket IgnorePublicAcls is enabled",
    "Policy Description": "This will block public access granted by ACLs while still allowing PUT Object calls that include a public ACL",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-publicaccessblockconfiguration.html#cfn-s3-bucket-publicaccessblockconfiguration-ignorepublicacls"
}



#
# PR-AWS-CFR-S3-021
#

default s3_block_public_policy = null

aws_issue["s3_block_public_policy"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    not resource.Properties.PublicAccessBlockConfiguration.BlockPublicPolicy
}

source_path[{"s3_block_public_policy": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    not resource.Properties.PublicAccessBlockConfiguration.BlockPublicPolicy
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "PublicAccessBlockConfiguration", "BlockPublicPolicy"]
        ],
    }
}

aws_issue["s3_block_public_policy"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    lower(resource.Properties.PublicAccessBlockConfiguration.BlockPublicPolicy) != "true"
}

source_path[{"s3_block_public_policy": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    lower(resource.Properties.PublicAccessBlockConfiguration.BlockPublicPolicy) != "true"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "PublicAccessBlockConfiguration", "BlockPublicPolicy"]
        ],
    }
}

s3_block_public_policy {
    lower(input.Resources[i].Type) == "aws::s3::bucket"
    not aws_issue["s3_block_public_policy"]
}

s3_block_public_policy = false {
    aws_issue["s3_block_public_policy"]
}

s3_block_public_policy_err = "Ensure S3 Bucket BlockPublicPolicy is enabled" {
    aws_issue["s3_block_public_policy"]
}

s3_block_public_policy_metadata := {
    "Policy Code": "PR-AWS-CFR-S3-021",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure S3 Bucket BlockPublicPolicy is enabled",
    "Policy Description": "If an AWS account is used to host a data lake or another business application, blocking public access will serve as an account-level guard against accidental public exposure.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-publicaccessblockconfiguration.html#cfn-s3-bucket-publicaccessblockconfiguration-blockpublicpolicy"
}


#
# PR-AWS-CFR-S3-022
#

default s3_notification_config = null

aws_issue["s3_notification_config"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    has_property(resource.Properties, "NotificationConfiguration")
}

s3_notification_config {
    lower(input.Resources[i].Type) == "aws::s3::bucket"
    not aws_issue["s3_notification_config"]
}

s3_notification_config = false {
    aws_issue["s3_notification_config"]
}

s3_notification_config_err = "Ensure S3 Bucket NotificationConfiguration Property is not set." {
    aws_issue["s3_notification_config"]
}

s3_notification_config_metadata := {
    "Policy Code": "PR-AWS-CFR-S3-022",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure S3 Bucket NotificationConfiguration Property is not set.",
    "Policy Description": "Prevent S3 Bucket NotificationConfiguration from being set denying notifications from being sent to any SNS Topics, SQS Queues or Lambda functions.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-publicaccessblockconfiguration.html#cfn-s3-bucket-publicaccessblockconfiguration-blockpublicpolicy"
}


#
# PR-AWS-CFR-S3-023
#

default s3_overly_permissive_to_any_principal = null

aws_issue["s3_overly_permissive_to_any_principal"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    stat := resource.Properties.PolicyDocument.Statement[_]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    startswith(lower(stat.Action),"s3:")
    not stat.Condition
}

aws_issue["s3_overly_permissive_to_any_principal"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    stat := resource.Properties.PolicyDocument.Statement[_]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    startswith(lower(stat.Action[_]),"s3:")
    not stat.Condition
}

s3_overly_permissive_to_any_principal {
    lower(input.Resources[i].Type) == "aws::s3::bucketpolicy"
    not aws_issue["s3_overly_permissive_to_any_principal"]
}

s3_overly_permissive_to_any_principal = false {
    aws_issue["s3_overly_permissive_to_any_principal"]
}

s3_overly_permissive_to_any_principal_err = "Ensure AWS S3 bucket policy is not overly permissive to any principal." {
    aws_issue["s3_overly_permissive_to_any_principal"]
}

s3_overly_permissive_to_any_principal_metadata := {
    "Policy Code": "PR-AWS-CFR-S3-023",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure AWS S3 bucket policy is not overly permissive to any principal.",
    "Policy Description": "It identifies the S3 buckets that have a bucket policy overly permissive to any principal. It is recommended to follow the principle of least privileges ensuring that the only restricted entities have permission on S3 operations instead of any anonymous. For more details: https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-bucket-user-policy-specifying-principal-intro.html",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-policy.html"
}


#
# PR-AWS-CFR-S3-024
#

default s3_has_a_policy_attached = null

aws_issue["s3_has_a_policy_attached"] {
    primary_resource := input.Resources[i]
    lower(primary_resource.Type) == "aws::s3::bucket"
    count([c | lower(input.Resources[j].Type) == "aws::s3::bucketpolicy"; c:=1]) == 0
}

aws_issue["s3_has_a_policy_attached"] {
    primary_resource := input.Resources[i]
    lower(primary_resource.Type) == "aws::s3::bucket"
    count([c | 
        resource := input.Resources[_];
        lower(resource.Type) == "aws::s3::bucketpolicy";
    	resource.Properties.Bucket.Ref == primary_resource.Properties.BucketName;
        resource.Properties.PolicyDocument.Statement
    	c:=1]
    ) == 0
}

s3_has_a_policy_attached {
    lower(input.Resources[i].Type) == "aws::s3::bucketpolicy"
    not aws_issue["s3_has_a_policy_attached"]
}

s3_has_a_policy_attached = false {
    aws_issue["s3_has_a_policy_attached"]
}

s3_has_a_policy_attached_err = "Ensure AWS S3 bucket has a policy attached." {
    aws_issue["s3_has_a_policy_attached"]
}

s3_has_a_policy_attached_metadata := {
    "Policy Code": "PR-AWS-CFR-S3-024",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure AWS S3 bucket has a policy attached.",
    "Policy Description": "S3 access can be defined at IAM and Bucket policy levels. It is recommended to leverage bucket policies as it provide much more granularity. This controls check if a bucket has a custom policy attached to it.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-policy.html"
}


#
# PR-AWS-CFR-S3-025
#

default policy_is_not_overly_permissive_to_vpc_endpoints = null

aws_issue["policy_is_not_overly_permissive_to_vpc_endpoints"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    stat := resource.Properties.PolicyDocument.Statement[_]
    lower(stat.Effect) == "allow"
    has_property(stat.Condition.StringEquals, "aws:SourceVpce")
    startswith(lower(stat.Action),"s3:*")
}

aws_issue["policy_is_not_overly_permissive_to_vpc_endpoints"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    stat := resource.Properties.PolicyDocument.Statement[_]
    lower(stat.Effect) == "allow"
    has_property(stat.Condition.StringEquals, "aws:SourceVpce")
    startswith(lower(stat.Action[_]),"s3:*")
}

aws_issue["policy_is_not_overly_permissive_to_vpc_endpoints"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    stat := resource.Properties.PolicyDocument.Statement[_]
    lower(stat.Effect) == "deny"
    has_property(stat.Condition.StringNotEquals, "aws:SourceVpce")
    startswith(lower(stat.Action),"s3:*")
}

aws_issue["policy_is_not_overly_permissive_to_vpc_endpoints"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    stat := resource.Properties.PolicyDocument.Statement[_]
    lower(stat.Effect) == "deny"
    contains(stat.Condition.StringNotEquals, "aws:SourceVpce")
    startswith(lower(stat.Action[_]),"s3:*")
}

policy_is_not_overly_permissive_to_vpc_endpoints {
    lower(input.Resources[i].Type) == "aws::s3::bucketpolicy"
    not aws_issue["policy_is_not_overly_permissive_to_vpc_endpoints"]
}

policy_is_not_overly_permissive_to_vpc_endpoints = false {
    aws_issue["policy_is_not_overly_permissive_to_vpc_endpoints"]
}

policy_is_not_overly_permissive_to_vpc_endpoints_err = "Ensure AWS S3 bucket do not have policy that is overly permissive to VPC endpoints." {
    aws_issue["policy_is_not_overly_permissive_to_vpc_endpoints"]
}

policy_is_not_overly_permissive_to_vpc_endpoints_metadata := {
    "Policy Code": "PR-AWS-CFR-S3-025",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure AWS S3 bucket do not have policy that is overly permissive to VPC endpoints.",
    "Policy Description": "It identifies S3 buckets that have the bucket policy overly permissive to VPC endpoints. It is recommended to follow the principle of least privileges ensuring that the VPC endpoints have only necessary permissions instead of full permission on S3 operations. NOTE: When applying the Amazon S3 bucket policies for VPC endpoints described in this section, you might block your access to the bucket without intending to do so. Bucket permissions that are intended to specifically limit bucket access to connections originating from your VPC endpoint can block all connections to the bucket. The policy might disable console access to the specified bucket because console requests don't originate from the specified VPC endpoint. So remediation should be done very carefully. For details refer https://docs.aws.amazon.com/AmazonS3/latest/dev/example-bucket-policies-vpc-endpoint.html",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-policy.html"
}


#
# PR-AWS-CFR-EFS-001
#

default efs_kms = null

aws_issue["efs_kms"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::efs::filesystem"
    not resource.Properties.KmsKeyId
}

source_path[{"efs_kms": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::efs::filesystem"
    not resource.Properties.KmsKeyId
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "KmsKeyId"]
        ],
    }
}

aws_issue["efs_kms"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::efs::filesystem"
    not startswith(resource.Properties.KmsKeyId, "arn:")
}

source_path[{"efs_kms": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::efs::filesystem"
    not startswith(resource.Properties.KmsKeyId, "arn:")
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "KmsKeyId"]
        ],
    }
}

efs_kms {
    lower(input.Resources[i].Type) == "aws::efs::filesystem"
    not aws_issue["efs_kms"]
}

efs_kms = false {
    aws_issue["efs_kms"]
}

efs_kms_err = "AWS Elastic File System (EFS) not encrypted using Customer Managed Key" {
    aws_issue["efs_kms"]
}

efs_kms_metadata := {
    "Policy Code": "PR-AWS-CFR-EFS-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Elastic File System (EFS) not encrypted using Customer Managed Key",
    "Policy Description": "This policy identifies Elastic File Systems (EFSs) which are encrypted with default KMS keys and not with Keys managed by Customer. It is a best practice to use customer managed KMS Keys to encrypt your EFS data. It gives you full control over the encrypted data.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-efs-filesystem.html"
}

#
# PR-AWS-CFR-EFS-002
#

default efs_encrypt = null

aws_issue["efs_encrypt"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::efs::filesystem"
    lower(resource.Properties.Encrypted) != "true"
}

source_path[{"efs_encrypt": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::efs::filesystem"
    lower(resource.Properties.Encrypted) != "true"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "Encrypted"]
        ],
    }
}

aws_bool_issue["efs_encrypt"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::efs::filesystem"
    not resource.Properties.Encrypted
}

source_path[{"efs_encrypt": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::efs::filesystem"
    not resource.Properties.Encrypted
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "Encrypted"]
        ],
    }
}

efs_encrypt {
    lower(input.Resources[i].Type) == "aws::efs::filesystem"
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
    "Policy Code": "PR-AWS-CFR-EFS-002",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Elastic File System (EFS) with encryption for data at rest disabled",
    "Policy Description": "This policy identifies Elastic File Systems (EFSs) for which encryption for data at rest disabled. It is highly recommended to implement at-rest encryption in order to prevent unauthorized users from reading sensitive data saved to EFS.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-efs-filesystem.html"
}

#
# PR-AWS-CFR-EBS-001
#

default ebs_encrypt = null


aws_issue["ebs_encrypt"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::volume"
    resource.Properties.Encrypted != "true"
}

source_path[{"efs_encrypt": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::volume"
    resource.Properties.Encrypted != "true"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "Encrypted"]
        ],
    }
}

aws_bool_issue["ebs_encrypt"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::volume"
    not resource.Properties.Encrypted
}

source_path[{"efs_encrypt": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::volume"
    not resource.Properties.Encrypted
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "Encrypted"]
        ],
    }
}

ebs_encrypt {
    lower(input.Resources[i].Type) == "aws::ec2::volume"
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
    "Policy Code": "PR-AWS-CFR-EBS-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS EBS volumes are not encrypted",
    "Policy Description": "This policy identifies the EBS volumes which are not encrypted. The snapshots that you take of an encrypted EBS volume are also encrypted and can be moved between AWS Regions as needed. You cannot share encrypted snapshots with other AWS accounts and you cannot make them public. It is recommended that EBS volume should be encrypted.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-ebs-volume.html"
}

#
# PR-AWS-CFR-BKP-001
#

default backup_public_access_disable = null

aws_issue["backup_public_access_disable"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::backup::backupvault"
    statement := resource.Properties.AccessPolicy.Statement[j]
    lower(statement.Effect) == "allow"
    statement.Principal == "*"
}

source_path[{"backup_public_access_disable": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::backup::backupvault"
    statement := resource.Properties.AccessPolicy.Statement[j]
    lower(statement.Effect) == "allow"
    statement.Principal == "*"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "AccessPolicy", "Statement", j, "Principal"]
        ],
    }
}

aws_issue["backup_public_access_disable"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::backup::backupvault"
    statement := resource.Properties.AccessPolicy.Statement[j]
    lower(statement.Effect) == "allow"
    statement.Principal.AWS == "*"
}

source_path[{"backup_public_access_disable": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::backup::backupvault"
    statement := resource.Properties.AccessPolicy.Statement[j]
    lower(statement.Effect) == "allow"
    statement.Principal.AWS == "*"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "AccessPolicy", "Statement", j, "Principal", "AWS"]
        ],
    }
}

aws_issue["backup_public_access_disable"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::backup::backupvault"
    statement := resource.Properties.AccessPolicy.Statement[j]
    lower(statement.Effect) == "allow"
    statement.Principal.AWS[_] = "*"
}

source_path[{"backup_public_access_disable": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::backup::backupvault"
    statement := resource.Properties.AccessPolicy.Statement[j]
    lower(statement.Effect) == "allow"
    statement.Principal.AWS[_] = "*"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "AccessPolicy", "Statement", j, "Principal", "AWS"]
        ],
    }
}


backup_public_access_disable {
    lower(input.Resources[i].Type) == "aws::backup::backupvault"
    not aws_issue["backup_public_access_disable"]
}

backup_public_access_disable = false {
    aws_issue["backup_public_access_disable"]
}

backup_public_access_disable_err = "Ensure Glacier Backup policy is not publicly accessible" {
    aws_issue["backup_public_access_disable"]
}

backup_public_access_disable_metadata := {
    "Policy Code": "PR-AWS-CFR-BKP-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure Glacier Backup policy is not publicly accessible",
    "Policy Description": "Public Glacier backup potentially expose existing interfaces to unwanted 3rd parties that can tap into an existing data stream, resulting in data leak to an unwanted party.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-backup-backupvault.html#cfn-backup-backupvault-accesspolicy"
}


#
# PR-AWS-CFR-TRF-001
#

default transer_server_public_expose = null

aws_issue["transer_server_public_expose"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::transfer::server"
    not resource.Properties.EndpointType
}

source_path[{"transer_server_public_expose": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::transfer::server"
    not resource.Properties.EndpointType
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "EndpointType"]
        ],
    }
}

aws_issue["transer_server_public_expose"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::transfer::server"
    lower(resource.Properties.EndpointType) != "vpc"
}

source_path[{"transer_server_public_expose": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::transfer::server"
    lower(resource.Properties.EndpointType) != "vpc"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "EndpointType"]
        ],
    }
}


transer_server_public_expose {
    lower(input.Resources[i].Type) == "aws::transfer::server"
    not aws_issue["transer_server_public_expose"]
}

transer_server_public_expose = false {
    aws_issue["transer_server_public_expose"]
}

transer_server_public_expose_err = "Ensure Transfer Server is not publicly exposed" {
    aws_issue["transer_server_public_expose"]
}

transer_server_public_expose_metadata := {
    "Policy Code": "PR-AWS-CFR-TRF-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure Transfer Server is not publicly exposed",
    "Policy Description": "It is recommended that you use VPC as the EndpointType. With this endpoint type, you have the option to directly associate up to three Elastic IPv4 addresses (BYO IP included) with your server's endpoint and use VPC security groups to restrict traffic by the client's public IP address. This is not possible with EndpointType set to VPC_ENDPOINT.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-server.html#cfn-transfer-server-endpointdetails"
}


#
# PR-AWS-CFR-TRF-002
#

default transfer_server_protocol = null

aws_issue["transfer_server_protocol"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::transfer::server"
    protocol := resource.Properties.Protocols[_]
    protocol == "FTP"
}

transfer_server_protocol {
    lower(input.Resources[i].Type) == "aws::transfer::server"
    not aws_issue["transfer_server_protocol"]
}

transfer_server_protocol = false {
    aws_issue["transfer_server_protocol"]
}

transfer_server_protocol_err = "Ensure Transfer Server is not use FTP protocol." {
    aws_issue["transfer_server_protocol"]
}

transfer_server_protocol_metadata := {
    "Policy Code": "PR-AWS-CFR-TRF-002",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure Transfer Server is not use FTP protocol.",
    "Policy Description": "It checks if FTP protocol is not used for AWS Transfer Family server.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-server.html#cfn-transfer-server-protocols"
}