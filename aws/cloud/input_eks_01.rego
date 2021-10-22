#
# PR-AWS-0051
#

package rule

default rulepass = false

# API: https://docs.aws.amazon.com/eks/latest/APIReference/API_DescribeCluster.html

rulepass = true {
    # lower(input.Type) == "aws::eks::cluster"
    input.cluster.resourcesVpcConfig.endpointPrivateAccess=true
    input.cluster.resourcesVpcConfig.endpointPublicAccess=false
}

metadata := {
    "Policy Code": "PR-AWS-0051",
    "Type": "Cloud",
    "Product": "AWS",
    "Language": "Cloud",
    "Policy Title": "AWS EKS cluster endpoint access publicly enabled",
    "Policy Description": "When you create a new cluster, Amazon EKS creates an endpoint for the managed Kubernetes API server that you use to communicate with your cluster (using Kubernetes management tools such as kubectl). By default, this API server endpoint is public to the internet, and access to the API server is secured using a combination of AWS Identity and Access Management (IAM) and native Kubernetes Role Based Access Control (RBAC).<br><br>This policy checks your Kubernetes cluster endpoint access and triggers an alert if publicly enabled.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/eks/latest/APIReference/API_DescribeCluster.html"
}
