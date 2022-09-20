package rule

#
# PR-AWS-TRF-AMF-001
#

default amplify_basic_auth = null

aws_issue["amplify_basic_auth"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_amplify_app"
    not resource.properties.enable_basic_auth
}

amplify_basic_auth {
    lower(input.resources[i].type) == "aws_amplify_app"
    not aws_issue["amplify_basic_auth"]
}

amplify_basic_auth = false {
    aws_issue["amplify_basic_auth"]
}

amplify_basic_auth_err = "Ensure AWS amplify has basic auth enabled." {
    aws_issue["amplify_basic_auth"]
} 

amplify_basic_auth_metadata := {
    "Policy Code": "PR-AWS-TRF-AMF-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure AWS amplify has basic auth enabled.",
    "Policy Description": "To enhance the security enable basic auth for Amplify. It Enables basic authorization for the autocreated branch. So for this, user requires to enter base64-encode authorization credentials.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/amplify_app"
}


#
# PR-AWS-TRF-AMF-002
#

default amplify_pr_preview = null

aws_issue["amplify_pr_preview"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_amplify_app"
    config := resource.properties.auto_branch_creation_config[_]
    not config.enable_pull_request_preview
}

amplify_pr_preview {
    lower(input.resources[i].type) == "aws_amplify_app"
    not aws_issue["amplify_pr_preview"]
}

amplify_pr_preview = false {
    aws_issue["amplify_pr_preview"]
}

amplify_pr_preview_err = "Ensure AWS amplify has Pull Request Preview enabled." {
    aws_issue["amplify_pr_preview"]
} 

amplify_pr_preview_metadata := {
    "Policy Code": "PR-AWS-TRF-AMF-002",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure AWS amplify has Pull Request Preview enabled.",
    "Policy Description": "Pull request previews are enabled for each branch that Amplify Console automatically creates for your app. Amplify Console creates previews by deploying your app to a unique URL whenever a pull request is opened for the branch. Development and QA teams can use this preview to test the pull request before it's merged into a production or integration branch.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/amplify_app"
}