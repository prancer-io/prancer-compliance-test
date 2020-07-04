package rule

default rulepass = true

# API: https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketWebsite.html
# ID: 362

rulepass = false {
   input.Website
}

rulepass == false {
   input.WebsiteConfiguration
}
