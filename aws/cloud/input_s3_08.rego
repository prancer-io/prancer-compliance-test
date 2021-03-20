#
# PR-AWS-0145
#

package rule

default rulepass = true

# API: https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketVersioning.html

rulepass = false {
    lower(resource.Type) == "aws::s3::bucket"
   lower(input.Versioning.Status) == "disabled"
}
