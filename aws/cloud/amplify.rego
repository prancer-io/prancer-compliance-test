package rule

#
# PR-AWS-CLD-AMF-001
# AWS::Amplify::App

default amplify_basic_auth = true

amplify_basic_auth = false {
    not input.app.enableBasicAuth
}

amplify_basic_auth_err = "Ensure AWS amplify has basic auth enabled." {
    not amplify_basic_auth
}

amplify_basic_auth_metadata := {
    "Policy Code": "PR-AWS-CLD-AMF-001",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS amplify has basic auth enabled.",
    "Policy Description": "To enhance the security enable basic auth for Amplify. It Enables basic authorization for the autocreated branch. So for this, user requires to enter base64-encode authorization credentials.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/amplify.html#Amplify.Client.get_app"
}

#
# PR-AWS-CLD-AMF-002
# AWS::Amplify::App

default amplify_pr_preview = true

amplify_pr_preview = false {
    input.app.enableAutoBranchCreation == true
    not input.app.autoBranchCreationConfig.enablePullRequestPreview
}

amplify_pr_preview_err = "Ensure AWS amplify has Pull Request Preview enabled." {
    not amplify_pr_preview
}

amplify_pr_preview_metadata := {
    "Policy Code": "PR-AWS-CLD-AMF-001",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS amplify has Pull Request Preview enabled.",
    "Policy Description": "Pull request previews are enabled for each branch that Amplify Console automatically creates for your app. Amplify Console creates previews by deploying your app to a unique URL whenever a pull request is opened for the branch. Development and QA teams can use this preview to test the pull request before it's merged into a production or integration branch.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/amplify.html#Amplify.Client.get_app"
}
