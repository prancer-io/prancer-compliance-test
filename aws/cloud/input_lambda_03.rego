#
# PR-AWS-0107
#

package rule

default rulepass = false

# API: https://docs.aws.amazon.com/lambda/latest/dg/API_GetFunction.html

rulepass {
    # lower(input.Type) == "aws::lambda::function"
    lower(input.Configuration.TracingConfig.Mode) != "passthrough"
}

metadata := {
    "Policy Code": "PR-AWS-0107",
    "Type": "Cloud",
    "Product": "AWS",
    "Language": "Cloud",
    "Policy Title": "AWS Lambda functions with tracing not enabled",
    "Policy Description": "TracingConfig is a property of the AWS::Lambda::Function resource that configures tracing settings for your AWS Lambda (Lambda) function. When enabled, AWS Lambda tracing acitivates AWS X-Ray service that collects information on requests that a specific function performed. It reduces the time and effort for debugging and diagnosing the errors.<br><br>The value can be either PassThrough or Active. If PassThrough, Lambda will only trace the request from an upstream service if it contains a tracing header with 'sampled=1'. If Active, Lambda will respect any tracing header it receives from an upstream service. If no tracing header is received, Lambda will call X-Ray for a tracing decision.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/lambda/latest/dg/API_GetFunction.html"
}

#If the active tracing is enabled with LAMBDA then test will pass
