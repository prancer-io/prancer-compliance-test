package rule

#
# PR-AWS-TRF-AG-001
#

default gateway_private = null

aws_attribute_absence["gateway_private"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_api_gateway_rest_api"
    not resource.properties.endpoint_configuration
}

source_path[{"gateway_private": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_api_gateway_rest_api"
    not resource.properties.endpoint_configuration

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "endpoint_configuration"]
        ],
    }
}

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

#
# PR-AWS-TRF-AG-004
#

default gateway_logging_enable = null

aws_attribute_absence["gateway_logging_enable"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_api_gateway_stage"
    not resource.properties.access_log_settings
}

source_path[{"gateway_logging_enable": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_api_gateway_stage"
    not resource.properties.access_log_settings
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "access_log_settings"]
        ],
    }
}

aws_issue["gateway_logging_enable"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_api_gateway_stage"
    access_log_settings := resource.properties.access_log_settings[j]
    not access_log_settings.destination_arn
}

source_path[{"gateway_logging_enable": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_api_gateway_stage"
    access_log_settings := resource.properties.access_log_settings[j]
    not access_log_settings.destination_arn
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "access_log_settings", j, "destination_arn"]
        ],
    }
}

aws_issue["gateway_logging_enable"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_api_gateway_stage"
    access_log_settings := resource.properties.access_log_settings[j]
    count(access_log_settings.destination_arn) == 0
}

source_path[{"gateway_logging_enable": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_api_gateway_stage"
    access_log_settings := resource.properties.access_log_settings[j]
    count(access_log_settings.destination_arn) == 0
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "access_log_settings", j, "destination_arn"]
        ],
    }
}

aws_issue["gateway_logging_enable"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_api_gateway_stage"
    access_log_settings := resource.properties.access_log_settings[j]
    access_log_settings.destination_arn == null
}

source_path[{"gateway_logging_enable": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_api_gateway_stage"
    access_log_settings := resource.properties.access_log_settings[j]
    access_log_settings.destination_arn == null
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "access_log_settings", j, "destination_arn"]
        ],
    }
}

gateway_logging_enable {
    lower(input.resources[i].type) == "aws_api_gateway_stage"
    not aws_issue["gateway_logging_enable"]
    not aws_attribute_absence["gateway_logging_enable"]
}

gateway_logging_enable = false {
    aws_issue["gateway_logging_enable"]
}

gateway_logging_enable = false {
    aws_attribute_absence["gateway_logging_enable"]
}

gateway_logging_enable_err = "Ensure that API Gateway has enabled access logging" {
    aws_issue["gateway_logging_enable"]
} else = "Ensure that API Gateway has enabled access logging" {
    aws_attribute_absence["gateway_logging_enable"]
}

gateway_logging_enable_metadata := {
    "Policy Code": "PR-AWS-TRF-AG-004",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that API Gateway has enabled access logging",
    "Policy Description": "Enabling the custom access logging option in API Gateway allows delivery of custom logs to CloudWatch Logs, which can be analyzed using CloudWatch Logs Insights. Using custom domain names in Amazon API Gateway allows insights into requests sent to each custom domain name.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_stage#access_log_settings"
}

#
# PR-AWS-TRF-AG-005
#

default gateway_tracing_enable = null

aws_attribute_absence["gateway_tracing_enable"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_api_gateway_stage"
    not resource.properties.xray_tracing_enabled
}

source_path[{"gateway_tracing_enable": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_api_gateway_stage"
    not resource.properties.xray_tracing_enabled

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "xray_tracing_enabled"]
        ],
    }
}

aws_bool_issue["gateway_tracing_enable"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_api_gateway_stage"
    resource.properties.xray_tracing_enabled == false
}

source_path[{"gateway_tracing_enable": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_api_gateway_stage"
    resource.properties.xray_tracing_enabled == false

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "xray_tracing_enabled"]
        ],
    }
}

aws_issue["gateway_tracing_enable"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_api_gateway_stage"
    lower(resource.properties.xray_tracing_enabled) == "false"
}

source_path[{"gateway_tracing_enable": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_api_gateway_stage"
    lower(resource.properties.xray_tracing_enabled) == "false"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "xray_tracing_enabled"]
        ],
    }
}

gateway_tracing_enable {
    lower(input.resources[i].type) == "aws_api_gateway_stage"
    not aws_issue["gateway_tracing_enable"]
    not aws_attribute_absence["gateway_tracing_enable"]
    not aws_bool_issue["gateway_tracing_enable"]
}

gateway_tracing_enable = false {
    aws_issue["gateway_tracing_enable"]
}

gateway_tracing_enable = false {
    aws_bool_issue["gateway_tracing_enable"]
}

gateway_tracing_enable = false {
    aws_attribute_absence["gateway_tracing_enable"]
}

gateway_tracing_enable_err = "AWS API gateway request authorization is not set" {
    aws_issue["gateway_tracing_enable"]
} else = "AWS API gateway request authorization is not set" {
    aws_bool_issue["gateway_tracing_enable"]
} else = "AWS API Gateway Authorizer type is absent" {
    aws_attribute_absence["gateway_tracing_enable"]
}

gateway_tracing_enable_metadata := {
    "Policy Code": "PR-AWS-TRF-AG-005",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure API Gateway has tracing enabled",
    "Policy Description": "With tracing enabled X-Ray can provide an end-to-end view of an entire HTTP request. You can use this to analyze latencies in APIs and their backend services",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_stage#xray_tracing_enabled"
}


#
# PR-AWS-TRF-AG-006
#

default gateway_method_public_access = null

aws_issue["gateway_method_public_access"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_api_gateway_method"
    not resource.properties.authorization
    not resource.properties.api_key_required
}

source_path[{"gateway_method_public_access": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_api_gateway_method"
    not resource.properties.authorization
    not resource.properties.api_key_required
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "api_key_required"]
        ],
    }
}

aws_issue["gateway_method_public_access"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_api_gateway_method"
    lower(resource.properties.authorization) == "none"
    not resource.properties.api_key_required
}

source_path[{"gateway_method_public_access": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_api_gateway_method"
    lower(resource.properties.authorization) == "none"
    not resource.properties.api_key_required
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "api_key_required"]
        ],
    }
}

aws_issue["gateway_method_public_access"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_api_gateway_method"
    resource.properties.authorization == null
    not resource.properties.api_key_required
}

source_path[{"gateway_method_public_access": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_api_gateway_method"
    resource.properties.authorization == null
    not resource.properties.api_key_required
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "api_key_required"]
        ],
    }
}

aws_issue["gateway_method_public_access"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_api_gateway_method"
    not resource.properties.authorization
    lower(resource.properties.api_key_required) != "true"
}

source_path[{"gateway_method_public_access": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_api_gateway_method"
    not resource.properties.authorization
    lower(resource.properties.api_key_required) != "true"
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "api_key_required"]
        ],
    }
}

aws_issue["gateway_method_public_access"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_api_gateway_method"
    lower(resource.properties.authorization) == "none"
    lower(resource.properties.api_key_required) != "true"
}

source_path[{"gateway_method_public_access": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_api_gateway_method"
    lower(resource.properties.authorization) == "none"
    lower(resource.properties.api_key_required) != "true"
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "api_key_required"]
        ],
    }
}

aws_issue["gateway_method_public_access"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_api_gateway_method"
    resource.properties.authorization == null
    lower(resource.properties.api_key_required) != "true"
}

source_path[{"gateway_method_public_access": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_api_gateway_method"
    resource.properties.authorization == null
    lower(resource.properties.api_key_required) != "true"
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "api_key_required"]
        ],
    }
}

gateway_method_public_access {
    lower(input.resources[i].type) == "aws_api_gateway_method"
    not aws_issue["gateway_method_public_access"]
}

gateway_method_public_access = false {
    aws_issue["gateway_method_public_access"]
}

gateway_method_public_access_err = "Ensure API gateway methods are not publicly accessible" {
    aws_issue["gateway_method_public_access"]
}

gateway_method_public_access_metadata := {
    "Policy Code": "PR-AWS-TRF-AG-006",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure API gateway methods are not publicly accessible",
    "Policy Description": "We recommend you configure a custom authorizer OR an API key for every method in the API Gateway.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_method#authorization"
}

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
# PR-AWS-TRF-AG-008
#

default api_gateway_not_configured_with_firewall_v2 = null

aws_issue["api_gateway_not_configured_with_firewall_v2"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_api_gateway_stage"
    not resource.properties.web_acl_arn
}

api_gateway_not_configured_with_firewall_v2 {
    lower(input.resources[i].type) == "aws_api_gateway_stage"
    not aws_issue["api_gateway_not_configured_with_firewall_v2"]
}

api_gateway_not_configured_with_firewall_v2 = false {
    aws_issue["api_gateway_not_configured_with_firewall_v2"]
}

api_gateway_not_configured_with_firewall_v2_err = "AWS API Gateway REST API is not configured with AWS Web Application Firewall v2 (AWS WAFv2)" {
    aws_issue["api_gateway_not_configured_with_firewall_v2"]
}

api_gateway_not_configured_with_firewall_v2_metadata := {
    "Policy Code": "PR-AWS-TRF-AG-008",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS API Gateway REST API is not configured with AWS Web Application Firewall v2 (AWS WAFv2)",
    "Policy Description": "AWS API Gateway REST API which is not configured with AWS Web Application Firewall. As a best practice, enable the AWS WAF service on API Gateway REST API to protect against application layer attacks. To block malicious requests to your API Gateway REST API, define the block criteria in the WAF web access control list (web ACL).",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_stage#web_acl_arn"
}

#
# PR-AWS-TRF-AG-009
#

default api_gateway_uses_specific_tls_version = null

aws_issue["api_gateway_uses_specific_tls_version"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_api_gateway_domain_name"
    resource.properties.security_policy != "TLS_1_2"
}

api_gateway_uses_specific_tls_version = false {
    aws_issue["api_gateway_uses_specific_tls_version"]
}

api_gateway_uses_specific_tls_version {
    lower(input.resources[i].type) == "aws_api_gateway_domain_name"
    not aws_issue["api_gateway_uses_specific_tls_version"]
}

api_gateway_uses_specific_tls_version_err = "Ensure AWS API Gateway uses TLS 1.2 in transit" {
    aws_issue["api_gateway_uses_specific_tls_version"]
}

api_gateway_uses_specific_tls_version_metadata := {
    "Policy Code": "PR-AWS-TRF-AG-009",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure AWS API Gateway uses TLS 1.2 in transit",
    "Policy Description": "Ensure AWS API Gateway uses Transport Layer Security (TLS) version TLS_1_2.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_domain_name#security_policy"
}

#
# PR-AWS-TRF-AG-010
#

default api_gateway_content_encoding_is_enabled = null

aws_issue["api_gateway_content_encoding_is_enabled"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_api_gateway_rest_api"
    not resource.properties.minimum_compression_size
}

api_gateway_content_encoding_is_enabled = false {
    aws_issue["api_gateway_content_encoding_is_enabled"]
}

api_gateway_content_encoding_is_enabled {
    lower(input.resources[i].type) == "aws_api_gateway_rest_api"
    not aws_issue["api_gateway_content_encoding_is_enabled"]
}

api_gateway_content_encoding_is_enabled_err = "Ensure content encoding is enabled for API Gateway." {
    aws_issue["api_gateway_content_encoding_is_enabled"]
}

api_gateway_content_encoding_is_enabled_metadata := {
    "Policy Code": "PR-AWS-TRF-AG-010",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure content encoding is enabled for API Gateway.",
    "Policy Description": "When compression is enabled, compression or decompression is not applied on the payload if the payload size is smaller than this value. Ensure content encoding is enabled for API Gateway.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/api_gateway_rest_api"
}