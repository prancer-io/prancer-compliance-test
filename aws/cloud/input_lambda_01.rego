#
# PR-AWS-0105
#

package rule

default rulepass = false

# API: https://docs.aws.amazon.com/lambda/latest/dg/API_GetFunction.html

rulepass {
    lower(input.Type) == "aws::lambda::function"
    input.Configuration.KMSKeyArn
}

# if the Lambda function encrypted the envrinment variables at the rest then test will pass
