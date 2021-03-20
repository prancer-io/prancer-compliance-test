#
# PR-AWS-0108
#

package rule

default rulepass = true

# API: https://docs.aws.amazon.com/lambda/latest/dg/API_GetFunction.html

rulepass = false {
    lower(resource.Type) == "aws::lambda::function"
   to_number(input.Configuration.CodeSize) > 67500000
}
