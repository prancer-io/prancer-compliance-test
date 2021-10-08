package rule
default metadata = {}

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html
# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-policy.html

#
# PR-AWS-0004-CFR
#

default s3_accesslog = null

aws_attribute_absence["s3_accesslog"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    not resource.Properties.LoggingConfiguration.DestinationBucketName
}

aws_path[{"s3_accesslog": metadata}] {
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

aws_path[{"s3_accesslog": metadata}] {
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

aws_path[{"s3_accesslog": metadata}] {
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

aws_path[{"s3_accesslog": metadata}] {
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
    "Policy Code": "PR-AWS-0004-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Access logging not enabled on S3 buckets",
    "Policy Description": "Checks for S3 buckets without access logging turned on. Access logging allows customers to view complete audit trail on sensitive workloads such as S3 buckets. It is recommended that Access logging is turned on for all S3 buckets to meet audit PR-AWS-0004-CFR-DESC compliance requirement",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html"
}


#
# PR-AWS-0140-CFR
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

aws_path[{"s3_acl_delete": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    not resource.Properties.PolicyDocument.Statement
    metadata := {
        "resource_path": [["Resources", i, "Properties", "PolicyDocument", "Statement"]],
    }
}

aws_path[{"s3_acl_delete": metadata}] {
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

aws_path[{"s3_acl_delete": metadata}] {
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

aws_path[{"s3_acl_delete": metadata}] {
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
    "Policy Code": "PR-AWS-0140-CFR",
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
# PR-AWS-0141-CFR
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


aws_path[{"s3_acl_get": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    not resource.Properties.PolicyDocument.Statement
    metadata := {
        "resource_path": [["Resources", i, "Properties", "PolicyDocument", "Statement"]],
    }
}

aws_path[{"s3_acl_get": metadata}] {
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

aws_path[{"s3_acl_get": metadata}] {
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

aws_path[{"s3_acl_get": metadata}] {
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
    "Policy Code": "PR-AWS-0141-CFR",
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
# PR-AWS-0142-CFR
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

aws_path[{"s3_acl_list": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    not resource.Properties.PolicyDocument.Statement
    metadata := {
        "resource_path": [["Resources", i, "Properties", "PolicyDocument", "Statement"]],
    }
}

aws_path[{"s3_acl_list": metadata}] {
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

aws_path[{"s3_acl_list": metadata}] {
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

aws_path[{"s3_acl_list": metadata}] {
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
    "Policy Code": "PR-AWS-0142-CFR",
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
# PR-AWS-0143-CFR
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

aws_path[{"s3_acl_put": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    not resource.Properties.PolicyDocument.Statement
    metadata := {
        "resource_path": [["Resources", i, "Properties", "PolicyDocument", "Statement"]],
    }
}

aws_path[{"s3_acl_put": metadata}] {
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

aws_path[{"s3_acl_put": metadata}] {
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

aws_path[{"s3_acl_put": metadata}] {
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
    "Policy Code": "PR-AWS-0143-CFR",
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
# PR-AWS-0144-CFR
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

aws_path[{"s3_cloudtrail": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudtrail::trail"
    lower(resource.Properties.IsLogging) == "false"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "IsLogging"],
        ],
    }
}

aws_path[{"s3_cloudtrail": metadata}] {
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
    "Policy Code": "PR-AWS-0144-CFR",
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
# PR-AWS-0145-CFR
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

aws_path[{"s3_versioning": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    not resource.Properties.VersioningConfiguration.Status
    metadata := {
        "resource_path": [["Resources", i, "Properties", "VersioningConfiguration", "Status"]],
    }
}

aws_path[{"s3_versioning": metadata}] {
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
    "Policy Code": "PR-AWS-0145-CFR",
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
# PR-AWS-0147-CFR
#

default s3_public_acl = null

aws_issue["s3_public_acl"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    resource.Properties.AccessControl == "PublicRead"
}

aws_path[{"s3_public_acl": metadata}] {
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
    "Policy Code": "PR-AWS-0147-CFR",
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
# PR-AWS-0148-CFR
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

aws_path[{"s3_transport": metadata}] {
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

aws_path[{"s3_transport": metadata}] {
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

aws_path[{"s3_transport": metadata}] {
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

aws_path[{"s3_transport": metadata}] {
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

aws_path[{"s3_transport": metadata}] {
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
    "Policy Code": "PR-AWS-0148-CFR",
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
# PR-AWS-0149-CFR
#

default s3_auth_acl = null

aws_issue["s3_auth_acl"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    resource.Properties.AccessControl == "AuthenticatedRead"
}

aws_path[{"s3_auth_acl": metadata}] {
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
    "Policy Code": "PR-AWS-0149-CFR",
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
# PR-AWS-0150-CFR
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

aws_path[{"s3_public_access": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    lower(resource.Properties.AccessControl) == "publicread"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "AccessControl"],
        ],
    }
}

aws_path[{"s3_public_access": metadata}] {
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
    "Policy Code": "PR-AWS-0150-CFR",
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
# PR-AWS-0151-CFR
#

default s3_encryption = null

aws_issue["s3_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    not resource.Properties.BucketEncryption.ServerSideEncryptionConfiguration
}

aws_path["s3_encryption"] {
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
    "Policy Code": "PR-AWS-0151-CFR",
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
# PR-AWS-0196-CFR
#

default s3_website = null

aws_issue["s3_website"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    resource.Properties.WebsiteConfiguration
}

aws_path[{"s3_website": metadata}] {
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
    "Policy Code": "PR-AWS-0196-CFR",
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
# PR-AWS-0246-CFR
#

default s3_cors = null

aws_issue["s3_cors"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    cors_rule := resource.Properties.CorsConfiguration.CorsRules[_]
    cors_rule.AllowedHeaders[_] == "*"
    cors_rule.AllowedMethods[_] == "*"
}

aws_path[{"s3_cors": metadata}] {
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
    "Policy Code": "PR-AWS-0246-CFR",
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
# PR-AWS-0301-CFR
#

default bucket_kms_encryption = null


aws_issue["bucket_kms_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    count(resource.Properties.BucketEncryption.ServerSideEncryptionConfiguration) == 0
}

aws_issue["bucket_kms_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    not resource.Properties.BucketEncryption.ServerSideEncryptionConfiguration
}

aws_issue["bucket_kms_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    ServerSideEncryptionConfiguration := resource.Properties.BucketEncryption.ServerSideEncryptionConfiguration[_]
    not ServerSideEncryptionConfiguration.BucketKeyEnabled
}

aws_issue["bucket_kms_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    ServerSideEncryptionConfiguration := resource.Properties.BucketEncryption.ServerSideEncryptionConfiguration[_]
    lower(ServerSideEncryptionConfiguration.BucketKeyEnabled) == "false"
}

aws_issue["bucket_kms_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    ServerSideEncryptionConfiguration := resource.Properties.BucketEncryption.ServerSideEncryptionConfiguration[_]
    lower(ServerSideEncryptionConfiguration.ServerSideEncryptionByDefault.SSEAlgorithm) != "aws:kms"
}

aws_issue["bucket_kms_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    ServerSideEncryptionConfiguration := resource.Properties.BucketEncryption.ServerSideEncryptionConfiguration[_]
    lower(ServerSideEncryptionConfiguration.ServerSideEncryptionByDefault.SSEAlgorithm) == "aws:kms"
    not ServerSideEncryptionConfiguration.ServerSideEncryptionByDefault.KMSMasterKeyID
}

aws_issue["bucket_kms_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    ServerSideEncryptionConfiguration := resource.Properties.BucketEncryption.ServerSideEncryptionConfiguration[_]
    lower(ServerSideEncryptionConfiguration.ServerSideEncryptionByDefault.SSEAlgorithm) == "aws:kms"
    count(ServerSideEncryptionConfiguration.ServerSideEncryptionByDefault.KMSMasterKeyID) == 0
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
    "Policy Code": "PR-AWS-0301-CFR",
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
# PR-AWS-0309-CFR
#

default s3_object_lock_enable = null

aws_issue["s3_object_lock_enable"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    not resource.Properties.ObjectLockEnabled
}

aws_issue["s3_object_lock_enable"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    lower(resource.Properties.ObjectLockEnabled) != "true"
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
    "Policy Code": "PR-AWS-0309-CFR",
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
# PR-AWS-0310-CFR
#

default s3_cross_region_replica = null

aws_issue["s3_cross_region_replica"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    Rules := resource.Properties.ReplicationConfiguration.Rules[j]
    not Rules.Destination
}

aws_issue["s3_cross_region_replica"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    not resource.Properties.ReplicationConfiguration
}

s3_cross_region_replica {
    lower(input.Resources[i].Type) == "aws::s3::bucket"
    not aws_issue["s3_cross_region_replica"]
}

s3_cross_region_replica = false {
    aws_issue["s3_cross_region_replica"]
}

s3_cross_region_replica_err = "Ensure S3 bucket has enabled lock configuration" {
    aws_issue["s3_cross_region_replica"]
}

s3_cross_region_replica_metadata := {
    "Policy Code": "PR-AWS-0310-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure S3 bucket has enabled lock configuration",
    "Policy Description": "Cross-region replication enables automatic, asynchronous copying of objects across S3 buckets. By default, replication supports copying new S3 objects after it is enabled",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-replicationconfiguration-rules.html#cfn-s3-bucket-replicationconfiguration-rules-destination"
}


#
# PR-AWS-0346-CFR
#

default s3_public_access_block = null

aws_issue["s3_public_access_block"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    not resource.Properties.PublicAccessBlockConfiguration.BlockPublicAcls
}

aws_issue["s3_public_access_block"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    lower(resource.Properties.PublicAccessBlockConfiguration.BlockPublicAcls) != "true"
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
    "Policy Code": "PR-AWS-0346-CFR",
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
# PR-AWS-0351-CFR
#

default s3_restrict_public_bucket = null

aws_issue["s3_restrict_public_bucket"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    not resource.Properties.PublicAccessBlockConfiguration.RestrictPublicBuckets
}

aws_issue["s3_restrict_public_bucket"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    lower(resource.Properties.PublicAccessBlockConfiguration.RestrictPublicBuckets) != "true"
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
    "Policy Code": "PR-AWS-0351-CFR",
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
# PR-AWS-0352-CFR
#

default s3_ignore_public_acl = null

aws_issue["s3_ignore_public_acl"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    not resource.Properties.PublicAccessBlockConfiguration.IgnorePublicAcls
}

aws_issue["s3_ignore_public_acl"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    lower(resource.Properties.PublicAccessBlockConfiguration.IgnorePublicAcls) != "true"
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
    "Policy Code": "PR-AWS-0352-CFR",
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
# PR-AWS-0353-CFR
#

default s3_block_public_policy = null

aws_issue["s3_block_public_policy"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    not resource.Properties.PublicAccessBlockConfiguration.BlockPublicPolicy
}

aws_issue["s3_block_public_policy"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    lower(resource.Properties.PublicAccessBlockConfiguration.BlockPublicPolicy) != "true"
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
    "Policy Code": "PR-AWS-0353-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure S3 Bucket BlockPublicPolicy is enabled",
    "Policy Description": "If an AWS account is used to host a data lake or another business application, blocking public access will serve as an account-level guard against accidental public exposure.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-publicaccessblockconfiguration.html#cfn-s3-bucket-publicaccessblockconfiguration-blockpublicpolicy"
}
