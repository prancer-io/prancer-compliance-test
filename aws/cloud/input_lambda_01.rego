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

metadata := {
    "Policy Code": "PR-AWS-0105",
    "Type": "Cloud",
    "Product": "AWS",
    "Language": "Cloud",
    "Policy Title": "AWS Lambda Environment Variables not encrypted at-rest using CMK",
    "Policy Description": "When you create or update Lambda functions that use environment variables, AWS Lambda encrypts them using the AWS Key Management Service. When your Lambda function is invoked, those values are decrypted and made available to the Lambda code._x005F_x000D_ _x005F_x000D_ This policy verifies that Lambda function uses the AMS Key Management Service to encrypt variables at-rest with CMK.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/lambda/latest/dg/API_GetFunction.html"
}

# if the Lambda function encrypted the envrinment variables at the rest then test will pass
