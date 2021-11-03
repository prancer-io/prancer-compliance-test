package rule


#
# PR-AWS-TRF-AG-007
#

default api_gw_cert = null

aws_issue["api_gw_cert"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_api_gateway_rest_api"
    not resource.properties.client_certificate_id
}


source_path[{"api_gw_cert": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_api_gateway_rest_api"
    not resource.properties.client_certificate_id

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "client_certificate_id"]
        ],
    }
}

aws_issue["api_gw_cert"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_api_gateway_rest_api"
    count(resource.properties.client_certificate_id) == 0
}

source_path[{"api_gw_cert": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_api_gateway_rest_api"
    count(resource.properties.client_certificate_id) == 0

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "client_certificate_id"]
        ],
    }
}

api_gw_cert {
    lower(input.resources[i].type) == "aws_api_gateway_rest_api"
    not aws_issue["api_gw_cert"]
}

api_gw_cert = false {
    aws_issue["api_gw_cert"]
}

api_gw_cert_err = "AWS API Gateway endpoints without client certificate authentication" {
    aws_issue["api_gw_cert"]
}

api_gw_cert_metadata := {
    "Policy Code": "PR-AWS-TRF-AG-007",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS API Gateway endpoints without client certificate authentication",
    "Policy Description": "API Gateway can generate an SSL certificate and use its public key in the backend to verify that HTTP requests to your backend system are from API Gateway. This allows your HTTP backend to control and accept only requests originating from Amazon API Gateway, even if the backend is publicly accessible._x005F_x000D_ _x005F_x000D_ Note: Some backend servers may not support SSL client authentication as API Gateway does and could return an SSL certificate error. For a list of incompatible backend servers, see Known Issues. https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-known-issues.html",
    "Resource Type": "aws_api_gateway_rest_api",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-apigateway-stage.html"
}

#
# PR-AWS-TRF-AG-001
#

default gateway_private = null

aws_attribute_absence["gateway_private"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_api_gateway_rest_api"
    endpoint_configuration := resource.properties.endpoint_configuration[j]
    not endpoint_configuration.types
}

source_path[{"gateway_private": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_api_gateway_rest_api"
    endpoint_configuration := resource.properties.endpoint_configuration[j]
    not endpoint_configuration.types

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "endpoint_configuration", j, "types"]
        ],
    }
}

aws_issue["gateway_private"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_api_gateway_rest_api"
    endpoint_configuration := resource.properties.endpoint_configuration[j]
    count(endpoint_configuration.types) == 0
}

source_path[{"gateway_private": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_api_gateway_rest_api"
    endpoint_configuration := resource.properties.endpoint_configuration[j]
    count(endpoint_configuration.types) == 0

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "endpoint_configuration", j, "types"]
        ],
    }
}

aws_issue["gateway_private"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_api_gateway_rest_api"
    endpoint_configuration := resource.properties.endpoint_configuration[j]
    type := endpoint_configuration.types[_]
    count([c | lower(type)== "private"; c:=1]) == 0
}

source_path[{"gateway_private": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_api_gateway_rest_api"
    endpoint_configuration := resource.properties.endpoint_configuration[j]
    type := endpoint_configuration.types[_]
    count([c | lower(type)== "private"; c:=1]) == 0

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "endpoint_configuration", j, "types"]
        ],
    }
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
    "Policy Code": "PR-AWS-TRF-AG-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "API Gateway should have API Endpoint type as private and not exposed to internet",
    "Policy Description": "Ensure that the Api endpoint type in api gateway is set to private and Is not exposed to the public internet",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-apigateway-restapi-endpointconfiguration.html"
}

#
# PR-AWS-TRF-AG-002
#

default gateway_validate_parameter = null

aws_bool_issue["gateway_validate_parameter"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_api_gateway_request_validator"
    not resource.properties.validate_request_parameters
}

source_path[{"gateway_validate_parameter": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_api_gateway_request_validator"
    not resource.properties.validate_request_parameters

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "validate_request_parameters"]
        ],
    }
}

aws_issue["gateway_validate_parameter"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_api_gateway_request_validator"
    lower(resource.properties.validate_request_parameters) == "false"
}

source_path[{"gateway_validate_parameter": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_api_gateway_request_validator"
    lower(resource.properties.validate_request_parameters) == "false"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "validate_request_parameters"]
        ],
    }
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
    "Policy Code": "PR-AWS-TRF-AG-002",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS API gateway request parameter is not validated",
    "Policy Description": "This policy identifies the AWS API gateways for with the request parameters are not validated. It is recommended to validate the request parameters in the URI, query string, and headers of an incoming request to focus on the validation efforts specific to your application.\n",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-apigateway-restapi-endpointconfiguration.html"
}

#
# PR-AWS-TRF-AG-003
#

default gateway_request_authorizer = null

aws_attribute_absence["gateway_request_authorizer"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_api_gateway_authorizer"
    not resource.properties.type
}

source_path[{"gateway_request_authorizer": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_api_gateway_authorizer"
    not resource.properties.type

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "type"]
        ],
    }
}

aws_issue["gateway_request_authorizer"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_api_gateway_authorizer"
    lower(resource.properties.type) != "request"
}

source_path[{"gateway_request_authorizer": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_api_gateway_authorizer"
    lower(resource.properties.type) != "request"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "type"]
        ],
    }
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
    "Policy Code": "PR-AWS-TRF-AG-003",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS API gateway request authorization is not set",
    "Policy Description": "This policy identifies AWS API Gateways of protocol type REST for which the request authorisation is not set. The method request for API gateways takes the client input that is passed to the back end through the integration request. It is recommended to add authorization type to each of the method to add a layer of protection.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-apigateway-restapi-endpointconfiguration.html"
}