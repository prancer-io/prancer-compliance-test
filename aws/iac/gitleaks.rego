package rule

# https://github.com/zricethezav/gitleaks/blob/master/examples/leaky-repo.toml

#
# PR-AWS-0001-RGX
#

default gl_aws_access_key = null

aws_issue["gl_aws_access_key"] {
    [path, value] := walk(input)
    regexp := "(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"
    regex.match(regexp, value)
}

gl_aws_access_key = false {
    aws_issue["gl_aws_access_key"]
}

gl_aws_access_key_err = "There is a possibility that AWS Access Key has leaked" {
    aws_issue["gl_aws_access_key"]
}

gl_aws_access_key_metadata := {
    "Policy Code": "PR-AWS-0001-RGX",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS ACM Certificate with wildcard domain name",
    "Policy Description": "This policy identifies ACM Certificates which are using wildcard certificates for wildcard domain name instead of single domain name certificates. ACM allows you to use an asterisk (*) in the domain name to create an ACM Certificate containing a wildcard name that can protect several sites in the same domain. For example, a wildcard certificate issued for *.<compliance-software>.io can match both www.<compliance-software>.io and images.<compliance-software>.io. When you use wildcard certificates, if the private key of a certificate is compromised, then all domain and subdomains that use the compromised certificate are potentially impacted. So it is recommended to use single domain name certificates instead of wildcard certificates to reduce the associated risks with a compromised domain or subdomain.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://github.com/zricethezav/gitleaks/blob/master/examples/leaky-repo.toml"
}

#
# PR-AWS-0002-RGX
#

default gl_aws_cred_file = null

aws_issue["gl_aws_cred_file"] {
    [path, value] := walk(input)
    regexp := "(?i)(aws_access_key_id|aws_secret_access_key)(.{0,20})?=.[0-9a-zA-Z\/+]{20,40}"
    regex.match(regexp, value)
}

gl_aws_cred_file = false {
    aws_issue["gl_aws_cred_file"]
}

gl_aws_cred_file_err = "There is a possibility that AWS cred file info has leaked" {
    aws_issue["gl_aws_cred_file"]
}

gl_aws_cred_file_metadata := {
    "Policy Code": "PR-AWS-0002-RGX",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS API Gateway endpoints without client certificate authentication",
    "Policy Description": "API Gateway can generate an SSL certificate and use its public key in the backend to verify that HTTP requests to your backend system are from API Gateway. This allows your HTTP backend to control and accept only requests originating from Amazon API Gateway, even if the backend is publicly accessible._x005F_x000D_ _x005F_x000D_ Note: Some backend servers may not support SSL client authentication as API Gateway does and could return an SSL certificate error. For a list of incompatible backend servers, see Known Issues. https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-known-issues.html",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://github.com/zricethezav/gitleaks/blob/master/examples/leaky-repo.toml"
}

#
# PR-AWS-0003-RGX
#

default gl_aws_secret_key = null

aws_issue["gl_aws_secret_key"] {
    [path, value] := walk(input)
    regexp := "(?i)aws(.{0,20})?(?-i)['\"][0-9a-zA-Z\/+]{40}['\"]"
    regex.match(regexp, value)
}

gl_aws_secret_key = false {
    aws_issue["gl_aws_secret_key"]
}

gl_aws_secret_key_err = "There is a possibility that AWS Secret Key has leaked" {
    aws_issue["gl_aws_secret_key"]
}

gl_aws_secret_key_metadata := {
    "Policy Code": "PR-AWS-0003-RGX",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Access key enabled on root account",
    "Policy Description": "This policy identifies root accounts for which access keys are enabled. Access keys are used to sign API requests to AWS. Root accounts have complete access to all your AWS services. If the access key for a root account is compromised, an unauthorized users will have complete access to your AWS account.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://github.com/zricethezav/gitleaks/blob/master/examples/leaky-repo.toml"
}

#
# PR-AWS-0004-RGX
#

default gl_aws_mws_key = null

aws_issue["gl_aws_mws_key"] {
    [path, value] := walk(input)
    regexp := "amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    regex.match(regexp, value)
}

gl_aws_mws_key = false {
    aws_issue["gl_aws_mws_key"]
}

gl_aws_mws_key_err = "There is a possibility that AWS MWS key has leaked" {
    aws_issue["gl_aws_mws_key"]
}

gl_aws_mws_key_metadata := {
    "Policy Code": "PR-AWS-0004-RGX",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Access logging not enabled on S3 buckets",
    "Policy Description": "Checks for S3 buckets without access logging turned on. Access logging allows customers to view complete audit trail on sensitive workloads such as S3 buckets. It is recommended that Access logging is turned on for all S3 buckets to meet audit PR-AWS-0004-RGX-DESC compliance requirement",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://github.com/zricethezav/gitleaks/blob/master/examples/leaky-repo.toml"
}

#
# PR-AWS-0005-RGX
#

default gl_fb_secret_key = null

aws_issue["gl_fb_secret_key"] {
    [path, value] := walk(input)
    regexp := "[0-9a-f]{32}"
    regex.match(regexp, value)
    regex.match("(?i)(facebook|fb)", path[_])
}

aws_issue["gl_fb_secret_key"] {
    [path, value] := walk(input)
    regexp := "(?i)(facebook|fb)(.{0,20})?(?-i)['\"][0-9a-f]{32}['\"]"
    regex.match(regexp, value)
}

gl_fb_secret_key = false {
    aws_issue["gl_fb_secret_key"]
}

gl_fb_secret_key_err = "There is a possibility that Facebook Secret Key has leaked" {
    aws_issue["gl_fb_secret_key"]
}

gl_fb_secret_key_metadata := {
    "Policy Code": "PR-AWS-0005-RGX",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Amazon Machine Image (AMI) is publicly accessible",
    "Policy Description": "This policy identifies AWS AMIs which are accessible to the public. Amazon Machine Image (AMI) provides information to launch an instance in the cloud. The AMIs may contain proprietary customer information and should be accessible only to authorized internal users.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://github.com/zricethezav/gitleaks/blob/master/examples/leaky-repo.toml"
}

#
# PR-AWS-0006-RGX
#

default gl_fb_client_id = null

aws_issue["gl_fb_client_id"] {
    [path, value] := walk(input)
    regexp := "[0-9]{13,17}"
    regex.match(regexp, value)
    regex.match("(?i)(facebook|fb)", path[_])
}

aws_issue["gl_fb_client_id"] {
    [path, value] := walk(input)
    regexp := "(?i)(facebook|fb)(.{0,20})?['\"][0-9]{13,17}['\"]"
    regex.match(regexp, value)
}

gl_fb_client_id = false {
    aws_issue["gl_fb_client_id"]
}

gl_fb_client_id_err = "There is a possibility that Facebook Client ID has leaked" {
    aws_issue["gl_fb_client_id"]
}

gl_fb_client_id_metadata := {
    "Policy Code": "PR-AWS-0006-RGX",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Application Load Balancer (ALB) listener that allow connection requests over HTTP",
    "Policy Description": "This policy identifies Application Load Balancer (ALB) listeners that are configured to accept connection requests over HTTP instead of HTTPS. As a best practice, use the HTTPS protocol to encrypt the communication between the application clients and the application load balancer.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://github.com/zricethezav/gitleaks/blob/master/examples/leaky-repo.toml"
}

#
# PR-AWS-0007-RGX
#

default gl_twit_secret_key = null

aws_issue["gl_twit_secret_key"] {
    [path, value] := walk(input)
    regexp := "[0-9a-z]{35,44}"
    regex.match(regexp, value)
    regex.match("(?i)twitter", path[_])
}

aws_issue["gl_twit_secret_key"] {
    [path, value] := walk(input)
    regexp := "(?i)twitter(.{0,20})?['\"][0-9a-z]{35,44}['\"]"
    regex.match(regexp, value)
}

gl_twit_secret_key = false {
    aws_issue["gl_twit_secret_key"]
}

gl_twit_secret_key_err = "There is a possibility that Twitter Secret Key has leaked" {
    aws_issue["gl_twit_secret_key"]
}

gl_twit_secret_key_metadata := {
    "Policy Code": "PR-AWS-0007-RGX",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Certificate Manager (ACM) contains certificate pending validation",
    "Policy Description": "This policy identifies invalid certificates which are in AWS Certificate Manager. When your Amazon ACM certificates are not validated within 72 hours after the request is made, those certificates become invalid and you will have to request new certificates, which could cause interruption to your applications or services. Though AWS Certificate Manager automatically renews certificates issued by the service that is used with other AWS resources. However, the ACM service does not automatically renew certificates that are not currently in use or not associated anymore with other AWS resources. So the renewal process including validation must be done manually before these certificates become invalid.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://github.com/zricethezav/gitleaks/blob/master/examples/leaky-repo.toml"
}

#
# PR-AWS-0008-RGX
#

default gl_twit_client_id = null

aws_issue["gl_twit_client_id"] {
    [path, value] := walk(input)
    regexp := "[0-9a-z]{18,25}"
    regex.match(regexp, value)
    regex.match("(?i)twitter", path[_])
}

aws_issue["gl_twit_client_id"] {
    [path, value] := walk(input)
    regexp := "(?i)twitter(.{0,20})?['\"][0-9a-z]{18,25}['\"]"
    regex.match(regexp, value)
}

gl_twit_client_id = false {
    aws_issue["gl_twit_client_id"]
}

gl_twit_client_id_err = "There is a possibility that Twitter Client ID has leaked" {
    aws_issue["gl_twit_client_id"]
}

gl_twit_client_id_metadata := {
    "Policy Code": "PR-AWS-0008-RGX",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Certificate Manager (ACM) has certificates expiring in 30 days or less",
    "Policy Description": "This policy identifies ACM certificates expiring in 30 days or less, which are in the AWS Certificate Manager. If SSL/TLS certificates are not renewed prior to their expiration date, they will become invalid and the communication between the client and the AWS resource that implements the certificates is no longer secure. As a best practice, it is recommended to renew certificates before their validity period ends. AWS Certificate Manager automatically renews certificates issued by the service that is used with other AWS resources. However, the ACM service does not renew automatically certificates that are not in use or not associated anymore with other AWS resources. So the renewal process must be done manually before these certificates become invalid._x005F_x000D_ _x005F_x000D_ NOTE: If you wanted to be notified other than before or less than 30 days; you can clone this policy and replace '30' in RQL with your desired days value. For example, 15 days OR 7 days which will alert certificates expiring in 15 days or less OR 7 days or less respectively.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://github.com/zricethezav/gitleaks/blob/master/examples/leaky-repo.toml"
}

#
# PR-AWS-0009-RGX
#

default gl_github_key = null

aws_issue["gl_github_key"] {
    [path, value] := walk(input)
    regexp := "[0-9a-zA-Z]{35,40}"
    regex.match(regexp, value)
    regex.match("(?i)github", path[_])
}

aws_issue["gl_github_key"] {
    [path, value] := walk(input)
    regexp := "(?i)github(.{0,20})?(?-i)['\"][0-9a-zA-Z]{35,40}['\"]"
    regex.match(regexp, value)
}

gl_github_key = false {
    aws_issue["gl_github_key"]
}

gl_github_key_err = "There is a possibility that Github key has leaked" {
    aws_issue["gl_github_key"]
}

gl_github_key_metadata := {
    "Policy Code": "PR-AWS-0009-RGX",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Certificate Manager (ACM) has certificates with Certificate Transparency Logging disabled",
    "Policy Description": "This policy identifies AWS Certificate Manager certificates in which Certificate Transparency Logging is disabled. AWS Certificate Manager (ACM) is the preferred tool to provision, manage, and deploy your server certificates. Certificate Transparency Logging is used to guard against SSL/TLS certificates that are issued by mistake or by a compromised CA, some browsers require that public certificates issued for your domain can also be recorded. This policy generates alerts for certificates which have transparency logging disabled. As a best practice, it is recommended to enable Transparency logging for all certificates.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://github.com/zricethezav/gitleaks/blob/master/examples/leaky-repo.toml"
}

#
# PR-AWS-0010-RGX
#

default gl_linkedin_client_id = null

aws_issue["gl_linkedin_client_id"] {
    [path, value] := walk(input)
    regexp := "[0-9a-z]{12}"
    regex.match(regexp, value)
    regex.match("(?i)linkedin", path[_])
}

aws_issue["gl_linkedin_client_id"] {
    [path, value] := walk(input)
    regexp := "(?i)linkedin(.{0,20})?(?-i)['\"][0-9a-z]{12}['\"]"
    regex.match(regexp, value)
}

gl_linkedin_client_id = false {
    aws_issue["gl_linkedin_client_id"]
}

gl_linkedin_client_id_err = "There is a possibility that LinkedIn Client ID has leaked" {
    aws_issue["gl_linkedin_client_id"]
}

gl_linkedin_client_id_metadata := {
    "Policy Code": "PR-AWS-0010-RGX",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Certificate Manager (ACM) has expired certificates",
    "Policy Description": "This policy identifies expired certificates which are in AWS Certificate Manager. AWS Certificate Manager (ACM) is the preferred tool to provision, manage, and deploy your server certificates. With ACM you can request a certificate or deploy an existing ACM or external certificate to AWS resources. This policy generates alerts if there are any expired ACM managed certificates. As a best practice, it is recommended to delete expired certificates.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://github.com/zricethezav/gitleaks/blob/master/examples/leaky-repo.toml"
}

#
# PR-AWS-0011-RGX
#

default gl_linkedin_key = null

aws_issue["gl_linkedin_key"] {
    [path, value] := walk(input)
    regexp := "[0-9a-z]{16}"
    regex.match(regexp, value)
    regex.match("(?i)linkedin", path[_])
}

aws_issue["gl_linkedin_key"] {
    [path, value] := walk(input)
    regexp := "(?i)linkedin(.{0,20})?['\"][0-9a-z]{16}['\"]"
    regex.match(regexp, value)
}

gl_linkedin_key = false {
    aws_issue["gl_linkedin_key"]
}

gl_linkedin_key_err = "There is a possibility that LinkedIn Secret Key has leaked" {
    aws_issue["gl_linkedin_key"]
}

gl_linkedin_key_metadata := {
    "Policy Code": "PR-AWS-0011-RGX",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Certificate Manager (ACM) has invalid or failed certificate",
    "Policy Description": "This policy identifies certificates in ACM which are either in Invalid or Failed state. If the ACM certificate is not validated within 72 hours, it becomes Invalid. An ACM certificate fails when, - the certificate is requested for invalid public domains - the certificate is requested for domains which are not allowed missing contact information - typographical errors In such cases (Invalid or Failed certificate), you will have to request for a new certificate. It is strongly recommended to delete the certificates which are in failed or invalid state.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://github.com/zricethezav/gitleaks/blob/master/examples/leaky-repo.toml"
}

#
# PR-AWS-0012-RGX
#

default gl_slack_key = null

aws_issue["gl_slack_key"] {
    [path, value] := walk(input)
    regexp := "xox[baprs]-([0-9a-zA-Z]{10,48})?"
    regex.match(regexp, value)
}

gl_slack_key = false {
    aws_issue["gl_slack_key"]
}

gl_slack_key_err = "There is a possibility that Slack Key has leaked" {
    aws_issue["gl_slack_key"]
}

gl_slack_key_metadata := {
    "Policy Code": "PR-AWS-0012-RGX",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Certificate Manager (ACM) has unused certificates",
    "Policy Description": "This policy identifies unused certificates which are in AWS Certificate Manager. AWS Certificate Manager (ACM) is the preferred tool to provision, manage, and deploy your server certificates. With ACM you can request a certificate or deploy an existing ACM or external certificate to AWS resources. This policy generates alerts if there are any unused ACM managed certificates. As a best practice, it is recommended to delete unused certificates or associate those certificates with any resources.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://github.com/zricethezav/gitleaks/blob/master/examples/leaky-repo.toml"
}

#
# PR-AWS-0013-RGX
#

default gl_ec_private_key = null

aws_issue["gl_ec_private_key"] {
    [path, value] := walk(input)
    regexp := "-----BEGIN EC PRIVATE KEY-----"
    regex.match(regexp, value)
}

gl_ec_private_key = false {
    aws_issue["gl_ec_private_key"]
}

gl_ec_private_key_err = "There is a possibility that EC Private Key has leaked" {
    aws_issue["gl_ec_private_key"]
}

gl_ec_private_key_metadata := {
    "Policy Code": "PR-AWS-0013-RGX",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS CloudFormation Template contains globally open resources",
    "Policy Description": "This alert triggers if a CloudFormation template that when launched will result in resources allowing global network access. Below are three common causes:_x005F_x000D_ _x005F_x000D_ - Security Group with a {0.0.0.0/0, ::/0} rule_x005F_x000D_ - Network Access Control List with a {0.0.0.0/0, ::/0} rule_x005F_x000D_ - Network Access Control List with -1 IpProtocol",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://github.com/zricethezav/gitleaks/blob/master/examples/leaky-repo.toml"
}

#
# PR-AWS-0014-RGX
#

default gl_google_api_key = null

aws_issue["gl_google_api_key"] {
    [path, value] := walk(input)
    regexp := "AIza[0-9A-Za-z\\-_]{35}"
    regex.match(regexp, value)
}

gl_google_api_key = false {
    aws_issue["gl_google_api_key"]
}

gl_google_api_key_err = "There is a possibility that Google API key has leaked" {
    aws_issue["gl_google_api_key"]
}

gl_google_api_key_metadata := {
    "Policy Code": "PR-AWS-0014-RGX",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS CloudFormation stack configured without SNS topic",
    "Policy Description": "This policy identifies CloudFormation stacks which are configured without SNS topic. It is recommended to configure Simple Notification Service (SNS) topic to be notified of CloudFormation stack status and changes.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://github.com/zricethezav/gitleaks/blob/master/examples/leaky-repo.toml"
}

#
# PR-AWS-0015-RGX
#

default gl_heroku_api_key = null

aws_issue["gl_heroku_api_key"] {
    [path, value] := walk(input)
    regexp := "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    regex.match(regexp, value)
    regex.match("(?i)heroku", path[_])
}

aws_issue["gl_heroku_api_key"] {
    [path, value] := walk(input)
    regexp := "(?i)heroku(.{0,20})?['\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]"
    regex.match(regexp, value)
}

gl_heroku_api_key = false {
    aws_issue["gl_heroku_api_key"]
}

gl_heroku_api_key_err = "There is a possibility that Heroku API key has leaked" {
    aws_issue["gl_heroku_api_key"]
}

gl_heroku_api_key_metadata := {
    "Policy Code": "PR-AWS-0015-RGX",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS CloudFront Distributions with Field-Level Encryption not enabled",
    "Policy Description": "This policy identifies CloudFront distributions for which field-level encryption is not enabled. Field-level encryption adds an additional layer of security along with HTTPS which protects specific data throughout system processing so that only certain applications can see it.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://github.com/zricethezav/gitleaks/blob/master/examples/leaky-repo.toml"
}

#
# PR-AWS-0016-RGX
#

default gl_mc_api_key = null

aws_issue["gl_mc_api_key"] {
    [path, value] := walk(input)
    regexp := "[0-9a-f]{32}-us[0-9]{1,2}"
    regex.match(regexp, value)
    regex.match("(?i)(mailchimp|mc)", path[_])
}

aws_issue["gl_mc_api_key"] {
    [path, value] := walk(input)
    regexp := "(?i)(mailchimp|mc)(.{0,20})?['\"][0-9a-f]{32}-us[0-9]{1,2}['\"]"
    regex.match(regexp, value)
}

gl_mc_api_key = false {
    aws_issue["gl_mc_api_key"]
}

gl_mc_api_key_err = "There is a possibility that MailChimp API key has leaked" {
    aws_issue["gl_mc_api_key"]
}

gl_mc_api_key_metadata := {
    "Policy Code": "PR-AWS-0016-RGX",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS CloudFront distribution is using insecure SSL protocols for HTTPS communication",
    "Policy Description": "CloudFront, a content delivery network (CDN) offered by AWS, is not using a secure cipher for distribution. It is a best security practice to enforce the use of secure ciphers TLSv1.0, TLSv1.1, and/or TLSv1.2 in a CloudFront Distribution's certificate configuration. This policy scans for any deviations from this practice and returns the results.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://github.com/zricethezav/gitleaks/blob/master/examples/leaky-repo.toml"
}

#
# PR-AWS-0017-RGX
#

default gl_mailgun_api_key = null

aws_issue["gl_mailgun_api_key"] {
    [path, value] := walk(input)
    regexp := "[0-9a-z]{32}"
    regex.match(regexp, value)
    regex.match("(?i)(mailgun|mg)", path[_])
}

aws_issue["gl_mailgun_api_key"] {
    [path, value] := walk(input)
    regexp := "(?i)[0-9a-z]{32}"
    regex.match(regexp, value)
}

gl_mailgun_api_key = false {
    aws_issue["gl_mailgun_api_key"]
}

gl_mailgun_api_key_err = "There is a possibility that Mailgun API key has leaked" {
    aws_issue["gl_mailgun_api_key"]
}

gl_mailgun_api_key_metadata := {
    "Policy Code": "PR-AWS-0017-RGX",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS CloudFront distribution with access logging disabled",
    "Policy Description": "This policy identifies CloudFront distributions which have access logging disabled. Enabling access log on distributions creates log files that contain detailed information about every user request that CloudFront receives. Access logs are available for web distributions. If you enable logging, you can also specify the Amazon S3 bucket that you want CloudFront to save files in.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://github.com/zricethezav/gitleaks/blob/master/examples/leaky-repo.toml"
}

#
# PR-AWS-0018-RGX
#

default gl_paypal_braintree_token = null

aws_issue["gl_paypal_braintree_token"] {
    [path, value] := walk(input)
    regexp := "access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}"
    regex.match(regexp, value)
}

gl_paypal_braintree_token = false {
    aws_issue["gl_paypal_braintree_token"]
}

gl_paypal_braintree_token_err = "There is a possibility that PayPal Braintree access token has leaked" {
    aws_issue["gl_paypal_braintree_token"]
}

gl_paypal_braintree_token_metadata := {
    "Policy Code": "PR-AWS-0018-RGX",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS CloudFront origin protocol policy does not enforce HTTPS-only",
    "Policy Description": "It is a best security practice to enforce HTTPS-only traffic between a CloudFront distribution and the origin. This policy scans for any deviations from this practice and returns the results.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://github.com/zricethezav/gitleaks/blob/master/examples/leaky-repo.toml"
}

#
# PR-AWS-0019-RGX
#

default gl_picatic_api_key = null

aws_issue["gl_picatic_api_key"] {
    [path, value] := walk(input)
    regexp := "sk_live_[0-9a-z]{32}"
    regex.match(regexp, value)
}

gl_picatic_api_key = false {
    aws_issue["gl_picatic_api_key"]
}

gl_picatic_api_key_err = "There is a possibility that Picatic API key has leaked" {
    aws_issue["gl_picatic_api_key"]
}

gl_picatic_api_key_metadata := {
    "Policy Code": "PR-AWS-0019-RGX",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS CloudFront viewer protocol policy is not configured with HTTPS",
    "Policy Description": "For web distributions, you can configure CloudFront to require that viewers use HTTPS to request your objects, so connections are encrypted when CloudFront communicates with viewers.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://github.com/zricethezav/gitleaks/blob/master/examples/leaky-repo.toml"
}

#
# PR-AWS-0020-RGX
#

default gl_slack_webhook = null

aws_issue["gl_slack_webhook"] {
    [path, value] := walk(input)
    regexp := "https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}"
    regex.match(regexp, value)
}

gl_slack_webhook = false {
    aws_issue["gl_slack_webhook"]
}

gl_slack_webhook_err = "There is a possibility that Slack Webhook has leaked" {
    aws_issue["gl_slack_webhook"]
}

gl_slack_webhook_metadata := {
    "Policy Code": "PR-AWS-0020-RGX",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS CloudFront web distribution that allow TLS versions 1.0 or lower",
    "Policy Description": "This policy identifies AWS CloudFront web distributions which are configured with TLS versions for HTTPS communication between viewers and CloudFront. As a best practice, use TLSv1.1_2016 or later as the minimum protocol version in your CloudFront distribution security policies.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://github.com/zricethezav/gitleaks/blob/master/examples/leaky-repo.toml"
}

#
# PR-AWS-0021-RGX
#

default gl_stripe_api_key = null

aws_issue["gl_stripe_api_key"] {
    [path, value] := walk(input)
    regexp := "[sk|rk]_live_[0-9a-zA-Z]{24}"
    regex.match(regexp, value)
    regex.match("(?i)stripe", path[_])
}

aws_issue["gl_stripe_api_key"] {
    [path, value] := walk(input)
    regexp := "(?i)stripe(.{0,20})?['\"][sk|rk]_live_[0-9a-zA-Z]{24}"
    regex.match(regexp, value)
}

gl_stripe_api_key = false {
    aws_issue["gl_stripe_api_key"]
}

gl_stripe_api_key_err = "There is a possibility that Stripe API key has leaked" {
    aws_issue["gl_stripe_api_key"]
}

gl_stripe_api_key_metadata := {
    "Policy Code": "PR-AWS-0021-RGX",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS CloudFront web distribution with AWS Web Application Firewall (AWS WAF) service disabled",
    "Policy Description": "This policy identifies Amazon CloudFront web distributions which have the AWS Web Application Firewall (AWS WAF) service disabled. As a best practice, enable the AWS WAF service on CloudFront web distributions to protect against application layer attacks. To block malicious requests to your Cloudfront Content Delivery Network, define the block criteria in the WAF web access control list (web ACL).",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://github.com/zricethezav/gitleaks/blob/master/examples/leaky-repo.toml"
}

#
# PR-AWS-0022-RGX
#

default gl_square_token = null

aws_issue["gl_square_token"] {
    [path, value] := walk(input)
    regexp := "sq0atp-[0-9A-Za-z\\-_]{22}"
    regex.match(regexp, value)
}

gl_square_token = false {
    aws_issue["gl_square_token"]
}

gl_square_token_err = "There is a possibility that Square access token has leaked" {
    aws_issue["gl_square_token"]
}

gl_square_token_metadata := {
    "Policy Code": "PR-AWS-0022-RGX",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS CloudFront web distribution with default SSL certificate",
    "Policy Description": "This policy identifies CloudFront web distributions which have a default SSL certificate to access CloudFront content. It is a best practice to use custom SSL Certificate to access CloudFront content. It gives you full control over the content data. custom SSL certificates also allow your users to access your content by using an alternate domain name. You can use a certificate stored in AWS Certificate Manager (ACM) or you can use a certificate stored in IAM.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://github.com/zricethezav/gitleaks/blob/master/examples/leaky-repo.toml"
}

#
# PR-AWS-0023-RGX
#

default gl_square_oauth = null

aws_issue["gl_square_oauth"] {
    [path, value] := walk(input)
    regexp := "sq0csp-[0-9A-Za-z\\-_]{43}"
    regex.match(regexp, value)
}

gl_square_oauth = false {
    aws_issue["gl_square_oauth"]
}

gl_square_oauth_err = "There is a possibility that Square OAuth secret has leaked" {
    aws_issue["gl_square_oauth"]
}

gl_square_oauth_metadata := {
    "Policy Code": "PR-AWS-0023-RGX",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS CloudFront web distribution with geo restriction disabled",
    "Policy Description": "This policy identifies CloudFront web distributions which have geo restriction feature disabled. Geo Restriction has the ability to block IP addresses based on Geo IP by whitelist or blacklist a country in order to allow or restrict users in specific locations from accessing web application content.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://github.com/zricethezav/gitleaks/blob/master/examples/leaky-repo.toml"
}

#
# PR-AWS-0024-RGX
#

default gl_twilio_api_key = null

aws_issue["gl_twilio_api_key"] {
    [path, value] := walk(input)
    regexp := "[0-9a-f]{32}"
    regex.match(regexp, value)
    regex.match("(?i)twilio", path[_])
}

aws_issue["gl_twilio_api_key"] {
    [path, value] := walk(input)
    regexp := "(?i)twilio(.{0,20})?['\"][0-9a-f]{32}['\"]"
    regex.match(regexp, value)
}

gl_twilio_api_key = false {
    aws_issue["gl_twilio_api_key"]
}

gl_twilio_api_key_err = "There is a possibility that Twilio API key has leaked" {
    aws_issue["gl_twilio_api_key"]
}

gl_twilio_api_key_metadata := {
    "Policy Code": "PR-AWS-0024-RGX",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS CloudTrail S3 buckets have not enabled MFA Delete",
    "Policy Description": "This policy identifies the S3 buckets which do not have Multi-Factor Authentication enabled for CloudTrails. For encryption of log files, CloudTrail defaults to use of S3 server-side encryption (SSE). We recommend adding an additional layer of security by adding MFA Delete to your S3 bucket. This will help to prevent deletion of CloudTrail logs without your explicit authorization. We also encourage you to use a bucket policy that places restrictions on which of your identity access management (IAM) users are allowed to delete S3 objects.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://github.com/zricethezav/gitleaks/blob/master/examples/leaky-repo.toml"
}

#
# PR-AWS-0025-RGX
#

default gl_env_var = null

aws_issue["gl_env_var"] {
    [path, value] := walk(input)
    regexp := "(?i)(apikey|secret|key|api|password|pass|pw|host)=[0-9a-zA-Z-_.{}]{4,120}"
    regex.match(regexp, value)
}

gl_env_var = false {
    aws_issue["gl_env_var"]
}

gl_env_var_err = "There is a possibility that Environment variable has leaked" {
    aws_issue["gl_env_var"]
}

gl_env_var_metadata := {
    "Policy Code": "PR-AWS-0025-RGX",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS CloudTrail bucket is publicly accessible",
    "Policy Description": "This policy identifies publicly accessible S3 buckets that store CloudTrail data. These buckets contains sensitive audit data and only authorized users and applications should have access.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://github.com/zricethezav/gitleaks/blob/master/examples/leaky-repo.toml"
}

#
# PR-AWS-0026-RGX
#

default gl_email = null

aws_issue["gl_email"] {
    [path, value] := walk(input)
    regexp := "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,4}"
    regex.match(regexp, value)
}

gl_email = false {
    aws_issue["gl_email"]
}

gl_email_err = "There is a possibility that Email has leaked" {
    aws_issue["gl_email"]
}

gl_email_metadata := {
    "Policy Code": "PR-AWS-0026-RGX",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS CloudTrail is not enabled in all regions",
    "Policy Description": "Checks to ensure that CloudTrail is enabled across all regions. AWS CloudTrail is a service that enables governance, compliance, operational PR-AWS-0026-RGX-DESC risk auditing of the AWS account. It is a compliance and security best practice to turn on CloudTrail across different regions to get a complete audit trail of activities across various services.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://github.com/zricethezav/gitleaks/blob/master/examples/leaky-repo.toml"
}

#
# PR-AWS-0027-RGX
#

default gl_wpconfig = null

aws_issue["gl_wpconfig"] {
    [path, value] := walk(input)
    regexp := "define(.{0,20})?(DB_CHARSET|NONCE_SALT|LOGGED_IN_SALT|AUTH_SALT|NONCE_KEY|DB_HOST|DB_PASSWORD|AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|DB_NAME|DB_USER)(.{0,20})?['|\"].{10,120}['|\"]"
    regex.match(regexp, value)
}

gl_wpconfig = false {
    aws_issue["gl_wpconfig"]
}

gl_wpconfig_err = "There is a possibility that WP-Config variable has leaked" {
    aws_issue["gl_wpconfig"]
}

gl_wpconfig_metadata := {
    "Policy Code": "PR-AWS-0027-RGX",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS CloudTrail log validation is not enabled in all regions",
    "Policy Description": "This policy identifies AWS CloudTrails in which log validation is not enabled in all regions. CloudTrail log file validation creates a digitally signed digest file containing a hash of each log that CloudTrail writes to S3. These digest files can be used to determine whether a log file was modified after CloudTrail delivered the log. It is recommended that file validation be enabled on all CloudTrails.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://github.com/zricethezav/gitleaks/blob/master/examples/leaky-repo.toml"
}

#
# PR-AWS-0028-RGX
#

default gl_aws_secrets = null

aws_issue["gl_aws_secrets"] {
    [path, value] := walk(input)
    regexp := "[0-9a-z]{32}"
    regex.match(regexp, value)
    regex.match("(?i)aws_?(secret)?_?(access)?_?key", path[_])
}

aws_issue["gl_aws_secrets"] {
    [path, value] := walk(input)
    regexp := "[A-Za-z0-9/\\+=]{40}"
    regex.match(regexp, value)
}

gl_aws_secrets = false {
    aws_issue["gl_aws_secrets"]
}

gl_aws_secrets_err = "There is a possibility that AWS secret has leaked" {
    aws_issue["gl_aws_secrets"]
}

gl_aws_secrets_metadata := {
    "Policy Code": "PR-AWS-0028-RGX",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS CloudTrail logs are not encrypted using Customer Master Keys (CMKs)",
    "Policy Description": "Checks to ensure that CloudTrail logs are encrypted. AWS CloudTrail is a service that enables governance, compliance, operational PR-AWS-0028-RGX-DESC risk auditing of the AWS account. It is a compliance and security best practice to encrypt the CloudTrail data since it may contain sensitive information.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://github.com/zricethezav/gitleaks/blob/master/examples/leaky-repo.toml"
}

#
# PR-AWS-0029-RGX
#

default gl_aws_account = null

aws_issue["gl_aws_account"] {
    [path, value] := walk(input)
    regexp := "[0-9a-z]{32}"
    regex.match(regexp, value)
    regex.match("((?i)aws_?(account)_?(id)?", path[_])
}

aws_issue["gl_aws_account"] {
    [path, value] := walk(input)
    regexp := "[0-9]{4}\\-?[0-9]{4}\\-?[0-9]{4}"
    regex.match(regexp, value)
}

gl_aws_account = false {
    aws_issue["gl_aws_account"]
}

gl_aws_account_err = "There is a possibility that AWS account ID has leaked" {
    aws_issue["gl_aws_account"]
}

gl_aws_account_metadata := {
    "Policy Code": "PR-AWS-0029-RGX",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS CloudTrail logs should integrate with CloudWatch for all regions",
    "Policy Description": "This policy identifies the Cloudtrails which is not integrated with cloudwatch for all regions. CloudTrail uses Amazon S3 for log file storage and delivery, so log files are stored durably. In addition to capturing CloudTrail logs within a specified S3 bucket for long term analysis, realtime analysis can be performed by configuring CloudTrail to send logs to CloudWatch Logs. For a trail that is enabled in all regions in an account, CloudTrail sends log files from all those regions to a CloudWatch Logs log group. It is recommended that CloudTrail logs be sent to CloudWatch Logs.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://github.com/zricethezav/gitleaks/blob/master/examples/leaky-repo.toml"
}
