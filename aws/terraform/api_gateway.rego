package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-apigateway-restapi-endpointconfiguration.html

#
# PR-AWS-0202-TRF
#

default gateway_private = null

aws_attribute_absence["gateway_private"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_api_gateway_rest_api"
    endpoint_configuration := resource.properties.endpoint_configuration[_]
    not endpoint_configuration.types
}

aws_issue["gateway_private"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_api_gateway_rest_api"
    endpoint_configuration := resource.properties.endpoint_configuration[_]
    count(endpoint_configuration.types) == 0
}

aws_issue["gateway_private"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_api_gateway_rest_api"
    endpoint_configuration := resource.properties.endpoint_configuration[_]
    type := endpoint_configuration.types[_]
    count([c | lower(type)== "private"; c:=1]) == 0
}

gateway_private {
    lower(input.resources[i].type) == "aws_api_gateway_rest_api"
    not aws_issue["gateway_private"]
    not aws_attribute_absence["gateway_private"]
}

gateway_private = false {
    aws_issue["gateway_private"]
}

gateway_private = false {
    aws_attribute_absence["gateway_private"]
}

gateway_private_err = "API Gateway should have API Endpoint type as private and not exposed to internet" {
    aws_issue["gateway_private"]
} else = "AWS RestApi endpoint_configuration.types is absent" {
    aws_attribute_absence["gateway_private"]
}

gateway_private_metadata := {
    "Policy Code": "PR-AWS-0202-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "API Gateway should have API Endpoint type as private and not exposed to internet",
    "Policy Description": "Ensure that the Api endpoint type in api gateway is set to private and Is not exposed to the public internet",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-apigateway-restapi-endpointconfiguration.html"
}


#
# PR-AWS-0203-TRF
#

default gateway_validate_parameter = null

aws_bool_issue["gateway_validate_parameter"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_api_gateway_request_validator"
    not resource.properties.validate_request_parameters
}

aws_issue["gateway_validate_parameter"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_api_gateway_request_validator"
    lower(resource.properties.validate_request_parameters) == "false"
}

gateway_validate_parameter {
    lower(input.resources[i].type) == "aws_api_gateway_request_validator"
    not aws_issue["gateway_validate_parameter"]
    not aws_bool_issue["gateway_validate_parameter"]
}

gateway_validate_parameter = false {
    aws_issue["gateway_validate_parameter"]
}

gateway_validate_parameter = false {
    aws_bool_issue["gateway_validate_parameter"]
}

gateway_validate_parameter_err = "AWS API Gateway request parameter is not validated" {
    aws_issue["gateway_validate_parameter"]
} else = "AWS API Gateway request parameter is not validated" {
    aws_bool_issue["gateway_validate_parameter"]
}

gateway_validate_parameter_metadata := {
    "Policy Code": "PR-AWS-0203-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS API gateway request parameter is not validated",
    "Policy Description": "This policy identifies the AWS API gateways for with the request parameters are not validated. It is recommended to validate the request parameters in the URI, query string, and headers of an incoming request to focus on the validation efforts specific to your application.\n",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-apigateway-restapi-endpointconfiguration.html"
}


#
# PR-AWS-0204-TRF
#

default gateway_request_authorizer = null

aws_attribute_absence["gateway_request_authorizer"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_api_gateway_authorizer"
    not resource.properties.type
}

aws_issue["gateway_request_authorizer"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_api_gateway_authorizer"
    lower(resource.properties.type) != "request"
}

gateway_request_authorizer {
    lower(input.resources[i].type) == "aws_api_gateway_authorizer"
    not aws_issue["gateway_request_authorizer"]
    not aws_attribute_absence["gateway_request_authorizer"]
}

gateway_request_authorizer = false {
    aws_issue["gateway_request_authorizer"]
}

gateway_request_authorizer = false {
    aws_attribute_absence["gateway_request_authorizer"]
}

gateway_request_authorizer_err = "AWS API gateway request authorization is not set" {
    aws_issue["gateway_request_authorizer"]
} else = "AWS API Gateway Authorizer type is absent" {
    aws_attribute_absence["gateway_request_authorizer"]
}

gateway_request_authorizer_metadata := {
    "Policy Code": "PR-AWS-0204-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS API gateway request authorization is not set",
    "Policy Description": "This policy identifies AWS API Gateways of protocol type REST for which the request authorisation is not set. The method request for API gateways takes the client input that is passed to the back end through the integration request. It is recommended to add authorization type to each of the method to add a layer of protection.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-apigateway-restapi-endpointconfiguration.html"
}
