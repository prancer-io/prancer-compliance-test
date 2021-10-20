#
# PR-AWS-0054
#

package rule

default rulepass = false

# API: https://docs.aws.amazon.com/eks/latest/APIReference/API_DescribeCluster.html

rulepass = true {
    # lower(input.Type) == "aws::eks::cluster"
    input.cluster.logging.clusterLogging[_].enabled=true
}

metadata := {
    "Policy Code": "PR-AWS-0054",
    "Type": "Cloud",
    "Product": "AWS",
    "Language": "Cloud",
    "Policy Title": "AWS EKS control plane logging disabled",
    "Policy Description": "Amazon EKS control plane logging provides audit and diagnostic logs directly from the Amazon EKS control plane to CloudWatch Logs in your account. These logs make it easy for you to secure and run your clusters. You can select the exact log types you need, and logs are sent as log streams to a group for each Amazon EKS cluster in CloudWatch.</br> </br> This policy generates an alert if control plane logging is disabled.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/eks/latest/APIReference/API_DescribeCluster.html"
}
