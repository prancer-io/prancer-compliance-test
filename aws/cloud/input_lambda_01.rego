package rule

default rulepass = false

rulepass = true{
   input.Configuration.KMSKeyArn
}

# if the Lambda function encrypted the envrinment variables at the rest then test will pass