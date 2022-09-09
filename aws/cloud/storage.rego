package rule

# 
# PR-AWS-CLD-S3-001
# 

default s3_accesslog = true

s3_accesslog = false {
    not input.LoggingEnabled
}

s3_accesslog = false {
    # lower(resource.Type) == "aws::s3::bucket"
    count(input.LoggingEnabled.TargetBucket) == 0
}

s3_accesslog = false {
    # lower(resource.Type) == "aws::s3::bucket"
    count(input.LoggingEnabled.TargetPrefix) == 0
}

s3_accesslog_err = "AWS Access logging not enabled on S3 buckets" {
    not s3_accesslog
}

s3_accesslog_metadata := {
    "Policy Code": "PR-AWS-CLD-S3-001",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS Access logging not enabled on S3 buckets",
    "Policy Description": "Checks for S3 buckets without access logging turned on. Access logging allows customers to view complete audit trail on sensitive workloads such as S3 buckets",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html"
}


#
# PR-AWS-CLD-S3-002
#

default s3_acl_delete = true

s3_acl_delete = false {
    # lower(resource.Type) == "aws::s3::bucketpolicy"
    policy := json.unmarshal(input.Policy)
    not policy.Statement
}

s3_acl_delete = false {
    # lower(resource.Type) == "aws::s3::bucketpolicy"
    policy := json.unmarshal(input.Policy)
    stat := policy.Statement[_]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    startswith(lower(stat.Action),"s3:delete")
}

s3_acl_delete = false {
    # lower(resource.Type) == "aws::s3::bucketpolicy"
    policy := json.unmarshal(input.Policy)
    stat := policy.Statement[_]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    startswith(lower(stat.Action[_]),"s3:delete")
}

s3_acl_delete_err = "AWS S3 Bucket has Global DELETE Permissions enabled via bucket policy" {
    not s3_acl_delete
}

s3_acl_delete_metadata := {
    "Policy Code": "PR-AWS-CLD-S3-002",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS S3 Bucket has Global DELETE Permissions enabled via bucket policy",
    "Policy Description": "This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to DELETE objects from a bucket. These permissions permit anyone, malicious or not, to DELETE objects from your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk loss or compromise of critical data by leaving this open.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html"
}

#
# PR-AWS-CLD-S3-003
#

default s3_acl_get = true

s3_acl_get = false {
    # lower(resource.Type) == "aws::s3::bucketpolicy"
    policy := json.unmarshal(input.Policy)
    not policy.Statement
}

s3_acl_get = false {
    # lower(resource.Type) == "aws::s3::bucketpolicy"
    policy := json.unmarshal(input.Policy)
    stat := policy.Statement[_]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    lower(stat.Action[_]) == "s3:*"
}

s3_acl_get = false {
    # lower(resource.Type) == "aws::s3::bucketpolicy"
    policy := json.unmarshal(input.Policy)
    stat := policy.Statement[_]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    startswith(lower(stat.Action),"s3:get")
}

s3_acl_get = false {
    # lower(resource.Type) == "aws::s3::bucketpolicy"
    policy := json.unmarshal(input.Policy)
    stat := policy.Statement[_]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    startswith(lower(stat.Action[_]),"s3:get")
}

s3_acl_get_err = "AWS S3 Bucket has Global get Permissions enabled via bucket policy" {
    not s3_acl_get
}

s3_acl_get_metadata := {
    "Policy Code": "PR-AWS-CLD-S3-003",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS S3 Bucket has Global GET Permissions enabled via bucket policy",
    "Policy Description": "This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to GET objects from a bucket. These permissions permit anyone, malicious or not, to GET objects from your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk loss or compromise of critical data by leaving this open.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html"
}

#
# PR-AWS-CLD-S3-004
#

default s3_acl_list = true

s3_acl_list = false {
    # lower(resource.Type) == "aws::s3::bucketpolicy"
    policy := json.unmarshal(input.Policy)
    not policy.Statement
}

s3_acl_list = false {
    # lower(resource.Type) == "aws::s3::bucketpolicy"
    policy := json.unmarshal(input.Policy)
    stat := policy.Statement[_]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    lower(stat.Action[_]) == "s3:*"
}

s3_acl_list = false {
    # lower(resource.Type) == "aws::s3::bucketpolicy"
    policy := json.unmarshal(input.Policy)
    stat := policy.Statement[_]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    startswith(lower(stat.Action),"s3:list")

}

s3_acl_list = false {
    # lower(resource.Type) == "aws::s3::bucketpolicy"
    policy := json.unmarshal(input.Policy)
    stat := policy.Statement[_]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    startswith(lower(stat.Action[_]),"s3:list")

}

s3_acl_list_err = "AWS S3 Bucket has Global list Permissions enabled via bucket policy" {
    not s3_acl_list
}

s3_acl_list_metadata := {
    "Policy Code": "PR-AWS-CLD-S3-004",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS S3 Bucket has Global LIST Permissions enabled via bucket policy",
    "Policy Description": "This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to LIST objects from a bucket. These permissions permit anyone, malicious or not, to LIST objects from your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk loss or compromise of critical data by leaving this open.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html"
}

#
# PR-AWS-CLD-S3-005
#

default s3_acl_put = true

s3_acl_put = false {
    # lower(resource.Type) == "aws::s3::bucketpolicy"
    policy := json.unmarshal(input.Policy)
    not policy.Statement
}

s3_acl_put = false {
    # lower(resource.Type) == "aws::s3::bucketpolicy"
    policy := json.unmarshal(input.Policy)
    stat := policy.Statement[_]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    lower(stat.Action[_]) == "s3:*"
}

s3_acl_put = false {
    # lower(resource.Type) == "aws::s3::bucketpolicy"
    policy := json.unmarshal(input.Policy)
    stat := policy.Statement[_]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    startswith(lower(stat.Action),"s3:put")

}

s3_acl_put = false {
    # lower(resource.Type) == "aws::s3::bucketpolicy"
    policy := json.unmarshal(input.Policy)
    stat := policy.Statement[_]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    startswith(lower(stat.Action[_]),"s3:put")
}

s3_acl_put_err = "AWS S3 Bucket has Global put Permissions enabled via bucket policy" {
    not s3_acl_put
}

s3_acl_put_metadata := {
    "Policy Code": "PR-AWS-CLD-S3-005",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS S3 Bucket has Global PUT Permissions enabled via bucket policy",
    "Policy Description": "This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to PUT objects into a bucket. These permissions permit anyone, malicious or not, to PUT objects into your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk compromise of critical data by leaving this open.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html"
}

#
# PR-AWS-CLD-S3-006
#

default s3_cloudtrail = false

s3_cloudtrail = true {
    # lower(resource.Type) == "aws::cloudtrail::trail"
    input.IsLogging == true
}

s3_cloudtrail_err = "AWS S3 CloudTrail buckets for which access logging is disabled" {
    not s3_cloudtrail
}

s3_cloudtrail_metadata := {
    "Policy Code": "PR-AWS-CLD-S3-006",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS S3 CloudTrail buckets for which access logging is disabled",
    "Policy Description": "This policy identifies S3 CloudTrail buckets for which access is disabled.S3 Bucket access logging generates access records for each request made to your S3 bucket. An access log record contains information such as the request type, the resources specified in the request worked, and the time and date the request was processed. It is recommended that bucket access logging be enabled on the CloudTrail S3 bucket",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html"
}

#
# PR-AWS-CLD-S3-007
#

default s3_versioning = false

s3_versioning = true {
    # lower(resource.Type) == "aws::s3::bucket"
    lower(input.Status) == "enabled"
}

s3_versioning_err = "AWS S3 Object Versioning is disabled" {
    not s3_versioning
}

s3_versioning_metadata := {
    "Policy Code": "PR-AWS-CLD-S3-007",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS S3 Object Versioning is disabled",
    "Policy Description": "This policy identifies the S3 buckets which have Object Versioning disabled. S3 Object Versioning is an important capability in protecting your data within a bucket. Once you enable Object Versioning, you cannot remove it; you can suspend Object Versioning at any time on a bucket if you do not wish for it to persist. It is recommended to enable Object Versioning on S3.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html"
}

# #
# # PR-AWS-CLD-S3-008
# #

# default s3_public_acl = null

# aws_issue["s3_public_acl"] {
#     # lower(resource.Type) == "aws::s3::bucket"
#     input.AccessControl == "PublicRead"
# }

# source_path[{"s3_public_acl": metadata}] {
#     # lower(resource.Type) == "aws::s3::bucket"
#     lower(input.AccessControl) == "publicread"
#     metadata := {
#         "resource_path": [["Resources", i, "Properties", "AccessControl"]],
#     }
# }

# s3_public_acl {
#     lower(input.Resources[i].Type) == "aws::s3::bucket"
#     not aws_issue["s3_public_acl"]
# }

# s3_public_acl = false {
#     aws_issue["s3_public_acl"]
# }

# s3_public_acl_err = "AWS S3 bucket has global view ACL permissions enabled." {
#     aws_issue["s3_public_acl"]
# }

# s3_public_acl_metadata := {
#     "Policy Code": "PR-AWS-CLD-S3-008",
#     "Type": "cloud",
#     "Product": "AWS",
#     "Language": "AWS Cloud",
#     "Policy Title": "AWS S3 bucket has global view ACL permissions enabled.",
#     "Policy Description": "This policy determines if any S3 bucket(s) has Global View ACL permissions enabled for the All Users group. These permissions allow external resources to see the permission settings associated to the object.",
#     "Resource Type": "",
#     "Policy Help URL": "",
#     "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html"
# }

#
# PR-AWS-CLD-S3-009
#

default s3_transport = true

s3_transport = false {
    # lower(resource.Type) == "aws::s3::bucketpolicy"
    policy := json.unmarshal(input.Policy)
    statement := policy.Statement[_]
    not statement.Condition.StringLike
    not statement.Condition.Bool
}

s3_transport = false {
    # lower(resource.Type) == "aws::s3::bucketpolicy"
    policy := json.unmarshal(input.Policy)
    statement := policy.Statement[_]
    statement.Condition.StringLike
    not statement.Condition.StringLike["aws:SecureTransport"]
}

s3_transport = false {
    # lower(resource.Type) == "aws::s3::bucketpolicy"
    policy := json.unmarshal(input.Policy)
    statement := policy.Statement[_]
    statement.Condition.StringLike
    lower(statement.Condition.StringLike["aws:SecureTransport"]) == "false"
}

s3_transport = false {
    # lower(resource.Type) == "aws::s3::bucketpolicy"
    policy := json.unmarshal(input.Policy)
    statement := policy.Statement[_]
    statement.Condition.Bool
    not statement.Condition.Bool["aws:SecureTransport"]
}

s3_transport = false {
    # lower(resource.Type) == "aws::s3::bucketpolicy"
    policy := json.unmarshal(input.Policy)
    statement := policy.Statement[_]
    statement.Condition.Bool
    lower(statement.Condition.Bool["aws:SecureTransport"]) == "false"
}

s3_transport_err = "AWS S3 bucket not configured with secure data transport policy" {
    not s3_transport
}

s3_transport_metadata := {
    "Policy Code": "PR-AWS-CLD-S3-009",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS S3 bucket not configured with secure data transport policy",
    "Policy Description": "This policy identifies S3 buckets which are not configured with secure data transport policy. AWS S3 buckets should enforce encryption of data over the network using Secure Sockets Layer (SSL). It is recommended to add a bucket policy that explicitly denies (Effect: Deny) all access (Action: s3:*) from anybody who browses (Principal: *) to Amazon S3 objects within an Amazon S3 bucket if they are not accessed through HTTPS (aws:SecureTransport: false).",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html"
}

# #
# # PR-AWS-CLD-S3-010
# #

# default s3_auth_acl = null

# aws_issue["s3_auth_acl"] {
#     # lower(resource.Type) == "aws::s3::bucket"
#     input.AccessControl == "AuthenticatedRead"
# }

# source_path[{"s3_auth_acl": metadata}] {
#     # lower(resource.Type) == "aws::s3::bucket"
#     lower(input.AccessControl) == "authenticatedread"
#     metadata := {
#         "resource_path": [
#             ["Resources", i, "Properties", "AccessControl"],
#         ],
#     }
# }

# s3_auth_acl {
#     lower(input.Resources[i].Type) == "aws::s3::bucket"
#     not aws_issue["s3_auth_acl"]
# }

# s3_auth_acl = false {
#     aws_issue["s3_auth_acl"]
# }

# s3_auth_acl_err = "AWS S3 buckets are accessible to any authenticated user." {
#     aws_issue["s3_auth_acl"]
# }

# s3_auth_acl_metadata := {
#     "Policy Code": "PR-AWS-CLD-S3-010",
#     "Type": "cloud",
#     "Product": "AWS",
#     "Language": "AWS Cloud",
#     "Policy Title": "AWS S3 buckets are accessible to any authenticated user.",
#     "Policy Description": "This policy identifies S3 buckets accessible to any authenticated AWS users. Amazon S3 allows customer to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example to host website content. However, these buckets often contain highly sensitive enterprise data which if left accessible to anyone with valid AWS credentials, may result in sensitive data leaks.",
#     "Resource Type": "",
#     "Policy Help URL": "",
#     "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html"
# }

# #
# # PR-AWS-CLD-S3-011
# #

# default s3_public_access = null

# aws_issue["s3_public_access"] {
#     # lower(resource.Type) == "aws::s3::bucket"
#     input.AccessControl == "PublicRead"
# }

# aws_issue["s3_public_access"] {
#     # lower(resource.Type) == "aws::s3::bucket"
#     input.AccessControl == "PublicReadWrite"
# }

# source_path[{"s3_public_access": metadata}] {
#     # lower(resource.Type) == "aws::s3::bucket"
#     lower(input.AccessControl) == "publicread"
#     metadata := {
#         "resource_path": [
#             ["Resources", i, "Properties", "AccessControl"],
#         ],
#     }
# }

# source_path[{"s3_public_access": metadata}] {
#     # lower(resource.Type) == "aws::s3::bucket"
#     lower(input.AccessControl) == "publicreadwrite"
#     metadata := {
#         "resource_path": [
#             ["Resources", i, "Properties", "AccessControl"],
#         ],
#     }
# }

# s3_public_access {
#     lower(input.Resources[i].Type) == "aws::s3::bucket"
#     not aws_issue["s3_public_access"]
# }

# s3_public_access = false {
#     aws_issue["s3_public_access"]
# }

# s3_public_access_err = "AWS S3 buckets are accessible to public" {
#     aws_issue["s3_public_access"]
# }

# s3_public_access_metadata := {
#     "Policy Code": "PR-AWS-CLD-S3-011",
#     "Type": "cloud",
#     "Product": "AWS",
#     "Language": "AWS Cloud",
#     "Policy Title": "AWS S3 buckets are accessible to public",
#     "Policy Description": "This policy identifies S3 buckets which are publicly accessible. Amazon S3 allows customers to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example, to host website content. However, these buckets often contain highly sensitive enterprise data which if left open to public may result in sensitive data leaks.",
#     "Resource Type": "",
#     "Policy Help URL": "",
#     "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html"
# }

#
# PR-AWS-CLD-S3-012
#

default s3_encryption = false

s3_encryption = true {
    # lower(resource.Type) == "aws::s3::bucket"
    input.ServerSideEncryptionConfiguration
}

s3_encryption_err = "AWS S3 buckets do not have server side encryption" {
    not s3_encryption
}

s3_encryption_metadata := {
    "Policy Code": "PR-AWS-CLD-S3-012",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS S3 buckets do not have server side encryption.",
    "Policy Description": "Customers can protect the data in S3 buckets using the AWS server-side encryption. If the server-side encryption is not turned on for S3 buckets with sensitive data, in the event of a data breach, malicious users can gain access to the data.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html"
}

#
# PR-AWS-CLD-S3-013
#

default s3_website = true

s3_website = false {
    # lower(resource.Type) == "aws::s3::bucket"
    input.IndexDocument
}

s3_website = false {
    # lower(resource.Type) == "aws::s3::bucket"
    input.ErrorDocument
}

s3_website = false {
    # lower(resource.Type) == "aws::s3::bucket"
    input.RedirectAllRequestsTo
}

s3_website = false {
    # lower(resource.Type) == "aws::s3::bucket"
    input.RoutingRules
}

s3_website_err = "S3 buckets with configurations set to host websites" {
    not s3_website
}

s3_website_metadata := {
    "Policy Code": "PR-AWS-CLD-S3-013",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "S3 buckets with configurations set to host websites",
    "Policy Description": "To host a website on AWS S3 you should configure a bucket as a website. This policy identifies all the S3 buckets that are configured to host websites. By frequently surveying these S3 buckets you can ensure that only authorized buckets are enabled to host websites. Make sure to disable static website hosting for unauthorized S3 buckets.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html"
}


#
# PR-AWS-CLD-S3-014
#

default s3_cors = true

s3_cors = false {
    # lower(resource.Type) == "aws::s3::bucket"
    cors_rule := input.CORSRules[_]
    cors_rule.AllowedHeaders[_] == "*"
    cors_rule.AllowedMethods[_] == "*"
}

s3_cors_err = "Ensure S3 hosted sites supported hardened CORS" {
    not s3_cors
}

s3_cors_metadata := {
    "Policy Code": "PR-AWS-CLD-S3-014",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure S3 hosted sites supported hardened CORS",
    "Policy Description": "Ensure that AllowedOrigins, AllowedMethods should not be set to *. this allows all cross site users to access s3 bucket and they have permission to manipulate data",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html#aws-properties-s3-bucket--seealso"
}


#
# PR-AWS-CLD-S3-015
#

default bucket_kms_encryption = true


bucket_kms_encryption = false {
    # lower(resource.Type) == "aws::s3::bucket"
    rules := input.ServerSideEncryptionConfiguration.Rules[j]
    not rules.BucketKeyEnabled
}

bucket_kms_encryption = false {
    # lower(resource.Type) == "aws::s3::bucket"
    rules := input.ServerSideEncryptionConfiguration.Rules[j]
    lower(rules.ServerSideEncryptionByDefault.SSEAlgorithm) != "aws:kms"
}

bucket_kms_encryption = false {
    # lower(resource.Type) == "aws::s3::bucket"
    rules := input.ServerSideEncryptionConfiguration.Rules[j]
    lower(rules.ServerSideEncryptionByDefault.SSEAlgorithm) == "aws:kms"
    count(rules.ServerSideEncryptionByDefault.KMSMasterKeyID) == 0
}


bucket_kms_encryption_err = "Ensure S3 bucket is encrypted using KMS" {
    not bucket_kms_encryption
}

bucket_kms_encryption_metadata := {
    "Policy Code": "PR-AWS-CLD-S3-015",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure S3 bucket is encrypted using KMS",
    "Policy Description": "Ensure that your AWS S3 buckets are configured to use Server-Side Encryption with customer managed CMKs instead of S3-Managed Keys (SSE-S3) in order to obtain a fine-grained control over Amazon S3 data-at-rest encryption and decryption process",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-serversideencryptionbydefault.html#cfn-s3-bucket-serversideencryptionbydefault-ssealgorithm"
}


#
# PR-AWS-CLD-S3-016
#

default s3_object_lock_enable = false

s3_object_lock_enable = true {
    # lower(resource.Type) == "aws::s3::bucket"
    lower(input.ObjectLockConfiguration.ObjectLockEnabled) == "enabled"
}

s3_object_lock_enable_err = "Ensure S3 bucket has enabled lock configuration" {
    not s3_object_lock_enable
}

s3_object_lock_enable_metadata := {
    "Policy Code": "PR-AWS-CLD-S3-016",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure S3 bucket has enabled lock configuration",
    "Policy Description": "Indicates whether this bucket has an Object Lock configuration enabled. Enable ObjectLockEnabled when you apply ObjectLockConfiguration to a bucket.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html#cfn-s3-bucket-objectlockenabled"
}


#
# PR-AWS-CLD-S3-017
#

default s3_cross_region_replica = true

s3_cross_region_replica = false {
    # lower(resource.Type) == "aws::s3::bucket"
    not input.ReplicationConfiguration
}

s3_cross_region_replica = false {
    # lower(resource.Type) == "aws::s3::bucket"
    count(input.ReplicationConfiguration.Rules) == 0
}

s3_cross_region_replica = false {
    # lower(resource.Type) == "aws::s3::bucket"
    Rules := input.ReplicationConfiguration.Rules[j]
    not Rules.Destination
}

s3_cross_region_replica_err = "Ensure S3 bucket cross-region replication is enabled" {
    not s3_cross_region_replica
}

s3_cross_region_replica_metadata := {
    "Policy Code": "PR-AWS-CLD-S3-017",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure S3 bucket cross-region replication is enabled",
    "Policy Description": "Cross-region replication enables automatic, asynchronous copying of objects across S3 buckets. By default, replication supports copying new S3 objects after it is enabled",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-replicationconfiguration-rules.html#cfn-s3-bucket-replicationconfiguration-rules-destination"
}


#
# PR-AWS-CLD-S3-018
#

default s3_public_access_block = true

s3_public_access_block = false {
    # lower(resource.Type) == "aws::s3::bucket"
    not input.PublicAccessBlockConfiguration.BlockPublicAcls
}

s3_public_access_block_err = "Ensure S3 Bucket has public access blocks" {
    not s3_public_access_block
}

s3_public_access_block_metadata := {
    "Policy Code": "PR-AWS-CLD-S3-018",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure S3 Bucket has public access blocks",
    "Policy Description": "We recommend you ensure S3 bucket has public access blocks. If the public access block is not attached it defaults to False",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-publicaccessblockconfiguration.html#cfn-s3-bucket-publicaccessblockconfiguration-blockpublicpolicy"
}


#
# PR-AWS-CLD-S3-019
#

default s3_restrict_public_bucket = true

s3_restrict_public_bucket = false {
    # lower(resource.Type) == "aws::s3::bucket"
    not input.PublicAccessBlockConfiguration.RestrictPublicBuckets
}

s3_restrict_public_bucket_err = "Ensure S3 bucket RestrictPublicBucket is enabled" {
    not s3_restrict_public_bucket
}

s3_restrict_public_bucket_metadata := {
    "Policy Code": "PR-AWS-CLD-S3-019",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure S3 bucket RestrictPublicBucket is enabled",
    "Policy Description": "Enabling this setting does not affect previously stored bucket policies. Public and cross-account access within any public bucket policy, including non-public delegation to specific accounts, is blocked",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-publicaccessblockconfiguration.html#cfn-s3-bucket-publicaccessblockconfiguration-restrictpublicbuckets"
}


#
# PR-AWS-CLD-S3-020
#

default s3_ignore_public_acl = true


s3_ignore_public_acl = false {
    # lower(resource.Type) == "aws::s3::bucket"
    not input.PublicAccessBlockConfiguration.IgnorePublicAcls
}

s3_ignore_public_acl_err = "Ensure S3 bucket IgnorePublicAcls is enabled" {
    not s3_ignore_public_acl
}

s3_ignore_public_acl_metadata := {
    "Policy Code": "PR-AWS-CLD-S3-020",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure S3 bucket IgnorePublicAcls is enabled",
    "Policy Description": "This will block public access granted by ACLs while still allowing PUT Object calls that include a public ACL",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-publicaccessblockconfiguration.html#cfn-s3-bucket-publicaccessblockconfiguration-ignorepublicacls"
}


#
# PR-AWS-CLD-S3-021
#

default s3_block_public_policy = true

s3_block_public_policy = false {
    # lower(resource.Type) == "aws::s3::bucket"
    not input.PublicAccessBlockConfiguration.BlockPublicPolicy
}

s3_block_public_policy_err = "Ensure S3 Bucket BlockPublicPolicy is enabled" {
    not s3_block_public_policy
}

s3_block_public_policy_metadata := {
    "Policy Code": "PR-AWS-CLD-S3-021",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure S3 Bucket BlockPublicPolicy is enabled",
    "Policy Description": "If an AWS account is used to host a data lake or another business application, blocking public access will serve as an account-level guard against accidental public exposure.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-publicaccessblockconfiguration.html#cfn-s3-bucket-publicaccessblockconfiguration-blockpublicpolicy"
}

#
# PR-AWS-CLD-S3-023
# aws::s3::bucketpolicy
#

default s3_overly_permissive_to_any_principal = true

s3_overly_permissive_to_any_principal = false {
    policy := json.unmarshal(input.Policy)
    not policy.Statement
}

s3_overly_permissive_to_any_principal = false {
    policy := json.unmarshal(input.Policy)
    stat := policy.Statement[_]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    startswith(lower(stat.Action),"s3:")
    not stat.Condition
}

s3_overly_permissive_to_any_principal = false {
    policy := json.unmarshal(input.Policy)
    stat := policy.Statement[_]
    lower(stat.Effect) == "allow"
    contains(stat.Principal, "*")
    startswith(lower(stat.Action[_]),"s3:")
    not stat.Condition
}

s3_overly_permissive_to_any_principal_err = "Ensure AWS S3 bucket policy is not overly permissive to any principal." {
    not s3_overly_permissive_to_any_principal
}

s3_overly_permissive_to_any_principal_metadata := {
    "Policy Code": "PR-AWS-CLD-S3-023",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS S3 bucket policy is not overly permissive to any principal.",
    "Policy Description": "It identifies the S3 buckets that have a bucket policy overly permissive to any principal. It is recommended to follow the principle of least privileges ensuring that the only restricted entities have permission on S3 operations instead of any anonymous. For more details: https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-bucket-user-policy-specifying-principal-intro.html",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3.html#S3.Client.get_bucket_policy"
}

#
# PR-AWS-CLD-S3-024
# aws::s3::bucketpolicy
#

default s3_has_a_policy_attached = true

s3_has_a_policy_attached = false {
    policy := json.unmarshal(input.Policy)
    not policy.Statement
}

s3_has_a_policy_attached_err = "Ensure AWS S3 bucket has a policy attached." {
    not s3_has_a_policy_attached
}

s3_has_a_policy_attached_metadata := {
    "Policy Code": "PR-AWS-CLD-S3-024",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS S3 bucket has a policy attached.",
    "Policy Description": "S3 access can be defined at IAM and Bucket policy levels. It is recommended to leverage bucket policies as it provide much more granularity. This controls check if a bucket has a custom policy attached to it.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3.html#S3.Client.get_bucket_policy"
}

#
# PR-AWS-CLD-S3-025
# aws::s3::bucketpolicy

default policy_is_not_overly_permissive_to_vpc_endpoints = true

policy_is_not_overly_permissive_to_vpc_endpoints = false {
    policy := json.unmarshal(input.Policy)
    stat := policy.Statement[_]
    contains(stat.Condition.StringNotEquals, "aws:SourceVpce")
    lower(stat.Effect) == "deny"
    startswith(lower(stat.Action),"s3:*")
}

policy_is_not_overly_permissive_to_vpc_endpoints = false {
    policy := json.unmarshal(input.Policy)
    stat := policy.Statement[_]
    contains(stat.Condition.StringNotEquals, "aws:SourceVpce")
    lower(stat.Effect) == "deny"
    startswith(lower(stat.Action[_]),"s3:*")
}

policy_is_not_overly_permissive_to_vpc_endpoints = false {
    policy := json.unmarshal(input.Policy)
    stat := policy.Statement[_]
    contains(stat.Condition.StringEquals, "aws:SourceVpce")
    lower(stat.Effect) == "allow"
    startswith(lower(stat.Action),"s3:*")
}

policy_is_not_overly_permissive_to_vpc_endpoints = false {
    policy := json.unmarshal(input.Policy)
    stat := policy.Statement[_]
    contains(stat.Condition.StringEquals, "aws:SourceVpce")
    lower(stat.Effect) == "allow"
    startswith(lower(stat.Action[_]),"s3:*")
}

policy_is_not_overly_permissive_to_vpc_endpoints_err = "Ensure AWS S3 bucket do not have policy that is overly permissive to VPC endpoints." {
    not policy_is_not_overly_permissive_to_vpc_endpoints
}

policy_is_not_overly_permissive_to_vpc_endpoints_metadata := {
    "Policy Code": "PR-AWS-CLD-S3-025",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS S3 bucket do not have policy that is overly permissive to VPC endpoints.",
    "Policy Description": "It identifies S3 buckets that have the bucket policy overly permissive to VPC endpoints. It is recommended to follow the principle of least privileges ensuring that the VPC endpoints have only necessary permissions instead of full permission on S3 operations. NOTE: When applying the Amazon S3 bucket policies for VPC endpoints described in this section, you might block your access to the bucket without intending to do so. Bucket permissions that are intended to specifically limit bucket access to connections originating from your VPC endpoint can block all connections to the bucket. The policy might disable console access to the specified bucket because console requests don't originate from the specified VPC endpoint. So remediation should be done very carefully. For details refer https://docs.aws.amazon.com/AmazonS3/latest/dev/example-bucket-policies-vpc-endpoint.html",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3.html#S3.Client.get_bucket_policy"
}

#
# PR-AWS-CLD-S3-026
#

default s3_only_owner_access = true

s3_only_owner_access = false {
    owner_id := input.Owner.ID
    not owner_id
}

s3_only_owner_access = false {
    owner_id := input.Owner.ID
    count(input.Grants) >= 1
    count([c | (input.Grants[_].Grantee.ID == owner_id); c:=1]) == 0    
}
    
s3_only_owner_access_err = "Ensure S3 bucket ACL is in use and any user other than the owner does not have any access on it." {
    not s3_only_owner_access
}

s3_only_owner_access_metadata := {
    "Policy Code": "PR-AWS-CLD-S3-026",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure S3 bucket ACL is in use and any user other than the owner does not have any access on it.",
    "Policy Description": "It ensure the S3 access control list only allowed owner permissions. It checks if other AWs accounts are granted Read/Write access to the S3 bucket.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3.html#S3.Client.get_bucket_acl"
}

#
# PR-AWS-CLD-EFS-001
#

default efs_kms = false


efs_kms = true {
    # lower(resource.Type) == "aws::efs::filesystem"
    FileSystems := input.FileSystems[_]
    startswith(FileSystems.KmsKeyId, "arn:")
}

efs_kms_err = "AWS Elastic File System (EFS) not encrypted using Customer Managed Key" {
    not efs_kms
}

efs_kms_metadata := {
    "Policy Code": "PR-AWS-CLD-EFS-001",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS Elastic File System (EFS) not encrypted using Customer Managed Key",
    "Policy Description": "This policy identifies Elastic File Systems (EFSs) which are encrypted with default KMS keys and not with Keys managed by Customer. It is a best practice to use customer managed KMS Keys to encrypt your EFS data. It gives you full control over the encrypted data.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-efs-filesystem.html"
}

#
# PR-AWS-CLD-EFS-002
#

default efs_encrypt = true

efs_encrypt = false {
    # lower(resource.Type) == "aws::efs::filesystem"
    FileSystems := input.FileSystems[_]
    not FileSystems.Encrypted
}

efs_encrypt_err = "AWS Elastic File System (EFS) with encryption for data at rest disabled" {
    not efs_encrypt
}

efs_encrypt_metadata := {
    "Policy Code": "PR-AWS-CLD-EFS-002",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS Elastic File System (EFS) with encryption for data at rest disabled",
    "Policy Description": "This policy identifies Elastic File Systems (EFSs) for which encryption for data at rest disabled. It is highly recommended to implement at-rest encryption in order to prevent unauthorized users from reading sensitive data saved to EFS.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-efs-filesystem.html"
}

#
# PR-AWS-CLD-EBS-001
#

default ebs_encrypt = true

ebs_encrypt = false {
    # lower(resource.Type) == "aws::ec2::volume"
    volumes := input.Volumes[_]
    volumes.Encrypted != true
}

ebs_encrypt_err = "AWS EBS volumes are not encrypted" {
    not ebs_encrypt
}

ebs_encrypt_metadata := {
    "Policy Code": "PR-AWS-CLD-EBS-001",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS EBS volumes are not encrypted",
    "Policy Description": "This policy identifies the EBS volumes which are not encrypted. The snapshots that you take of an encrypted EBS volume are also encrypted and can be moved between AWS Regions as needed. You cannot share encrypted snapshots with other AWS accounts and you cannot make them public. It is recommended that EBS volume should be encrypted.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-ebs-volume.html"
}

#
# PR-AWS-CLD-BKP-001
#

default backup_public_access_disable = true

backup_public_access_disable = false {
    # lower(resource.Type) == "aws::backup::backupvault"
    policy := json.unmarshal(input.Policy)
    statement := policy.Statement[_]
    lower(statement.Effect) == "allow"
    statement.Principal == "*"
}

backup_public_access_disable = false {
    # lower(resource.Type) == "aws::backup::backupvault"
    policy := json.unmarshal(input.Policy)
    statement := policy.Statement[j]
    lower(statement.Effect) == "allow"
    statement.Principal.AWS == "*"
}

backup_public_access_disable = false {
    # lower(resource.Type) == "aws::backup::backupvault"
    policy := json.unmarshal(input.Policy)
    statement := policy.Statement[j]
    lower(statement.Effect) == "allow"
    statement.Principal.AWS[_] = "*"
}

backup_public_access_disable_err = "Ensure Glacier Backup policy is not publicly accessible" {
    not backup_public_access_disable
}

backup_public_access_disable_metadata := {
    "Policy Code": "PR-AWS-CLD-BKP-001",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure Glacier Backup policy is not publicly accessible",
    "Policy Description": "Public Glacier backup potentially expose existing interfaces to unwanted 3rd parties that can tap into an existing data stream, resulting in data leak to an unwanted party.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-backup-backupvault.html#cfn-backup-backupvault-policy"
}


#
# PR-AWS-CLD-TRF-001
#

default transer_server_public_expose = false

transer_server_public_expose = true {
    # lower(resource.Type) == "aws::transfer::server"
    lower(input.Server.EndpointType) == "vpc"
}

transer_server_public_expose_err = "Ensure Transfer Server is not publicly exposed" {
    not transer_server_public_expose
}

transer_server_public_expose_metadata := {
    "Policy Code": "PR-AWS-CLD-TRF-001",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure Transfer Server is not publicly exposed",
    "Policy Description": "It is recommended that you use VPC as the EndpointType. With this endpoint type, you have the option to directly associate up to three Elastic IPv4 addresses (BYO IP included) with your server's endpoint and use VPC security groups to restrict traffic by the client's public IP address. This is not possible with EndpointType set to VPC_ENDPOINT.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-transfer-server.html#cfn-transfer-server-endpointdetails"
}


#
# PR-AWS-CLD-TRF-002
# aws::transfer::server

default transfer_server_protocol = true

transfer_server_protocol = false {
    protocol := input.Server.Protocols[_]
    protocol == "FTP"
}

transfer_server_protocol_err = "Ensure Transfer Server is not use FTP protocol." {
    not transfer_server_protocol
}

transfer_server_protocol_metadata := {
    "Policy Code": "PR-AWS-CLD-TRF-002",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure Transfer Server is not use FTP protocol.",
    "Policy Description": "It checks if FTP protocol is not used for AWS Transfer Family server.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/transfer.html#Transfer.Client.describe_server"
}