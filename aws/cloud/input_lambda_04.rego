#
# PR-AWS-0108
#

package rule

default rulepass = true

# API: https://docs.aws.amazon.com/lambda/latest/dg/API_GetFunction.html

rulepass = false {
    lower(input.Type) == "aws::lambda::function"
    to_number(input.Configuration.CodeSize) > 67500000
}

metadata := {
    "Policy Code": "PR-AWS-0108",
    "Type": "Cloud",
    "Product": "AWS",
    "Language": "Cloud",
    "Policy Title": "AWS Lambda nearing availability code storage limit",
    "Policy Description": "This policy identifies Lambda nearing availability code storage limit per region. AWS provides a reasonable starting amount of compute and storage resources that you can use to run and store functions. As a best practice, it is recommended to either remove the functions that you no longer in use or reduce the code size of the functions that you do not want to remove. It will also help you avoid unexpected charges on your bill._x005F_x000D_ NOTE: As per https://docs.aws.amazon.com/lambda/latest/dg/limits.html. On the date, Lambda account limit per region is 75 GB. This policy will trigger an alert if Lambda account limit per region reached to 90% (i.e. 67500000 KB) of resource availability limit allocated. If you need more Lambda account code storage size per region, You can contact AWS for a service limit increase.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/lambda/latest/dg/API_GetFunction.html"
}
