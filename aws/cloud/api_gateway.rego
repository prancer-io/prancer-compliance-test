package rule

#
# PR-AWS-CLD-AG-001
#

# get_rest_api

default gateway_private = true

gateway_private = false {
    # lower(resource.Type) == "aws::apigateway::restapi"
    count(input.endpointConfiguration.types) == 0
}

gateway_private = false {
    type := input.endpointConfiguration.types[j]
    count([c | lower(type) == "private"; c:=1]) == 0
}

gateway_private_err = "API Gateway should have API Endpoint type as private and not exposed to internet" {
    not gateway_private
}

gateway_private_metadata := {
    "Policy Code": "PR-AWS-CLD-AG-001",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "API Gateway should have API Endpoint type as private and not exposed to internet",
    "Policy Description": "Ensure that the Api endpoint type in api gateway is set to private and Is not exposed to the public internet",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-apigateway-restapi-endpointconfiguration.html"
}


#
# PR-AWS-CLD-AG-002
#

# get_request_validators

default gateway_validate_parameter = true

gateway_validate_parameter = false {
    # lower(resource.Type) == "aws::apigateway::requestvalidator"
    items := input.items[_]
    items.validateRequestParameters == false
}

gateway_validate_parameter_err = "AWS API Gateway request parameter is not validated" {
    not gateway_validate_parameter
}

gateway_validate_parameter_metadata := {
    "Policy Code": "PR-AWS-CLD-AG-002",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS API gateway request parameter is not validated",
    "Policy Description": "This policy identifies the AWS API gateways for with the request parameters are not validated. It is recommended to validate the request parameters in the URI, query string, and headers of an incoming request to focus on the validation efforts specific to your application.\n",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-apigateway-restapi-endpointconfiguration.html"
}


#
# PR-AWS-CLD-AG-003
#

# get_authorizers

default gateway_request_authorizer = true

gateway_request_authorizer = false {
    # lower(resource.Type) == "aws::apigateway::authorizer"
    items := input.items[_]
    lower(items.type) != "request"
}

gateway_request_authorizer_err = "AWS API gateway request authorization is not set" {
    not gateway_request_authorizer
}

gateway_request_authorizer_metadata := {
    "Policy Code": "PR-AWS-CLD-AG-003",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS API gateway request authorization is not set",
    "Policy Description": "This policy identifies AWS API Gateways of protocol type REST for which the request authorisation is not set. The method request for API gateways takes the client input that is passed to the back end through the integration request. It is recommended to add authorization type to each of the method to add a layer of protection.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-apigateway-restapi-endpointconfiguration.html"
}


#
# PR-AWS-CLD-AG-004
#

# get_stages

default gateway_logging_enable = true

gateway_logging_enable = false {
    # lower(input.Resources[i].Type) == "aws::apigateway::stage"
    item := input.item[_]
    count(item.accessLogSettings.destinationArn) == 0
}

gateway_logging_enable = false {
    not input.accessLogSettings.destinationArn
}

gateway_logging_enable_err = "Ensure that API Gateway has enabled access logging" {
    not gateway_logging_enable
}

gateway_logging_enable_metadata := {
    "Policy Code": "PR-AWS-CLD-AG-004",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure that API Gateway has enabled access logging",
    "Policy Description": "Enabling the custom access logging option in API Gateway allows delivery of custom logs to CloudWatch Logs, which can be analyzed using CloudWatch Logs Insights. Using custom domain names in Amazon API Gateway allows insights into requests sent to each custom domain name.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-apigateway-stage.html"
}


#
# PR-AWS-CLD-AG-005
#

# get_stages

default gateway_tracing_enable = true

gateway_tracing_enable = false {
    # lower(resource.Type) == "aws::apigateway::stage"
    item := input.item[_]
    item.tracingEnabled != true
}

gateway_tracing_enable_err = "Ensure API Gateway has tracing enabled" {
    not gateway_tracing_enable
}

gateway_tracing_enable_metadata := {
    "Policy Code": "PR-AWS-CLD-AG-005",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure API Gateway has tracing enabled",
    "Policy Description": "With tracing enabled X-Ray can provide an end-to-end view of an entire HTTP request. You can use this to analyze latencies in APIs and their backend services",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-apigateway-stage.html"
}


#
# PR-AWS-CLD-AG-006
#

# get_resources

default gateway_method_public_access = true

gateway_method_public_access = false {
    # lower(resource.Type) == "aws::apigateway::method"
    some string
    items := input.items[_]
    lower(items.resourceMethods[string].authorizationType) == "none"
    not items.resourceMethods[string].apiKeyRequired
}

gateway_method_public_access_err = "Ensure API gateway methods are not publicly accessible" {
    not gateway_method_public_access
}

gateway_method_public_access_metadata := {
    "Policy Code": "PR-AWS-CLD-AG-006",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure API gateway methods are not publicly accessible",
    "Policy Description": "We recommend you configure a custom authorizer OR an API key for every method in the API Gateway.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-apigateway-method.html#cfn-apigateway-method-authorizationtype"
}



#
# PR-AWS-CLD-AG-007
#

# get_stages

default api_gw_cert = true

api_gw_cert = false {
    # lower(resource.Type) == "aws::apigateway::stage"
    item := input.item[_]
    count(item.clientcertificateId) == 0
}

api_gw_cert = false {
    # lower(resource.Type) == "aws::apigateway::stage"
    item := input.item[_]
    not item.clientcertificateId
}

api_gw_cert_err = "AWS API Gateway endpoints without client certificate authentication" {
    not api_gw_cert
}

api_gw_cert_metadata := {
    "Policy Code": "PR-AWS-CLD-AG-007",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS API Gateway endpoints without client certificate authentication",
    "Policy Description": "API Gateway can generate an SSL certificate and use its public key in the backend to verify that HTTP requests to your backend system are from API Gateway. This allows your HTTP backend to control and accept only requests originating from Amazon API Gateway, even if the backend is publicly accessible._x005F_x000D_ _x005F_x000D_ Note: Some backend servers may not support SSL client authentication as API Gateway does and could return an SSL certificate error. For a list of incompatible backend servers, see Known Issues. https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-known-issues.html",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-apigateway-stage.html"
}