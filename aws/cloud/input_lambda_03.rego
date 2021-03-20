#
# PR-AWS-0107
#

package rule

default rulepass = false

# API: https://docs.aws.amazon.com/lambda/latest/dg/API_GetFunction.html

rulepass {
    lower(resource.Type) == "aws::lambda::function"
    lower(input.Configuration.TracingConfig.Mode) != "passthrough"
}

#If the active tracing is enabled with LAMBDA then test will pass
