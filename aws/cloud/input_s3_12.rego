#
# PR-AWS-0196
#

package rule

default rulepass = true

# API: https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketWebsite.html

rulepass = false {
   input.Website
}

rulepass == false {
   input.WebsiteConfiguration
}
