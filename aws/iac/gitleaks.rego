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
    regexp := "(?i)(mailgun|mg)(.{0,20})?['\"][0-9a-z]{32}['\"]"
    regex.match(regexp, value)
}

gl_mailgun_api_key = false {
    aws_issue["gl_mailgun_api_key"]
}

gl_mailgun_api_key_err = "There is a possibility that Mailgun API key has leaked" {
    aws_issue["gl_mailgun_api_key"]
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
