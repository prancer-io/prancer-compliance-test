package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-apigateway-restapi-endpointconfiguration.html

#
# PR-AWS-CFR-AG-001
#

default gateway_private = null

aws_attribute_absence["gateway_private"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::apigateway::restapi"
    not resource.Properties.EndpointConfiguration.Types
}

source_path[{"gateway_private": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::apigateway::restapi"
    not resource.Properties.EndpointConfiguration.Types
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "EndpointConfiguration", "Types"]
        ],
    }
}

aws_issue["gateway_private"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::apigateway::restapi"
    count(resource.Properties.EndpointConfiguration.Types) == 0
}

source_path[{"gateway_private": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::apigateway::restapi"
    count(resource.Properties.EndpointConfiguration.Types) == 0
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "EndpointConfiguration", "Types"]
        ],
    }
}

aws_issue["gateway_private"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::apigateway::restapi"
    type := resource.Properties.EndpointConfiguration.Types[j]
    count([c | lower(type)== "private"; c:=1]) == 0
}

source_path[{"gateway_private": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::apigateway::restapi"
    type := resource.Properties.EndpointConfiguration.Types[j]
    count([c | lower(type)== "private"; c:=1]) == 0
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "EndpointConfiguration", "Types"]
        ],
    }
}

gateway_private {
    lower(input.Resources[i].Type) == "aws::apigateway::restapi"
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
} else = "AWS RestApi EndpointConfiguration.Type is absent" {
    aws_attribute_absence["gateway_private"]
}

gateway_private_metadata := {
    "Policy Code": "PR-AWS-CFR-AG-001",
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
# PR-AWS-CFR-AG-002
#

default gateway_validate_parameter = null

aws_bool_issue["gateway_validate_parameter"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::apigateway::requestvalidator"
    not resource.Properties.ValidateRequestParameters
}

source_path[{"gateway_validate_parameter": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::apigateway::requestvalidator"
    not resource.Properties.ValidateRequestParameters
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "ValidateRequestParameters"]
        ],
    }
}

aws_issue["gateway_validate_parameter"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::apigateway::requestvalidator"
    lower(resource.Properties.ValidateRequestParameters) == "false"
}

source_path[{"gateway_validate_parameter": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::apigateway::requestvalidator"
    lower(resource.Properties.ValidateRequestParameters) == "false"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "ValidateRequestParameters"]
        ],
    }
}

gateway_validate_parameter {
    lower(input.Resources[i].Type) == "aws::apigateway::requestvalidator"
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
    "Policy Code": "PR-AWS-CFR-AG-002",
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
# PR-AWS-CFR-AG-003
#

default gateway_request_authorizer = null

aws_attribute_absence["gateway_request_authorizer"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::apigateway::authorizer"
    not resource.Properties.Type
}

source_path[{"gateway_request_authorizer": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::apigateway::authorizer"
    not resource.Properties.Type
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "Type"]
        ],
    }
}

aws_issue["gateway_request_authorizer"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::apigateway::authorizer"
    lower(resource.Properties.Type) != "request"
}

source_path[{"gateway_request_authorizer": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::apigateway::authorizer"
    lower(resource.Properties.Type) != "request"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "Type"]
        ],
    }
}

gateway_request_authorizer {
    lower(input.Resources[i].Type) == "aws::apigateway::authorizer"
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
    "Policy Code": "PR-AWS-CFR-AG-003",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS API gateway request authorization is not set",
    "Policy Description": "This policy identifies AWS API Gateways of protocol type REST for which the request authorisation is not set. The method request for API gateways takes the client input that is passed to the back end through the integration request. It is recommended to add authorization type to each of the method to add a layer of protection.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-apigateway-restapi-endpointconfiguration.html"
}


#
# PR-AWS-CFR-AG-004
#

default gateway_logging_enable = null

aws_issue["gateway_logging_enable"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::apigateway::stage"
    not resource.Properties.AccessLogSetting.DestinationArn
}

source_path[{"gateway_logging_enable": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::apigateway::stage"
    not resource.Properties.AccessLogSetting.DestinationArn
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "AccessLogSetting", "DestinationArn"]
        ],
    }
}

aws_issue["gateway_logging_enable"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::apigateway::stage"
    count(resource.Properties.AccessLogSetting.DestinationArn) == 0
}

source_path[{"gateway_logging_enable": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::apigateway::stage"
    count(resource.Properties.AccessLogSetting.DestinationArn) == 0
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "AccessLogSetting", "DestinationArn"]
        ],
    }
}

aws_issue["gateway_logging_enable"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::apigateway::stage"
    resource.Properties.AccessLogSetting.DestinationArn == null
}

source_path[{"gateway_logging_enable": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::apigateway::stage"
    resource.Properties.AccessLogSetting.DestinationArn == null
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "AccessLogSetting", "DestinationArn"]
        ],
    }
}

gateway_logging_enable {
    lower(input.Resources[i].Type) == "aws::apigateway::stage"
    not aws_issue["gateway_logging_enable"]
}

gateway_logging_enable = false {
    aws_issue["gateway_logging_enable"]
}

gateway_logging_enable_err = "Ensure that API Gateway has enabled access logging" {
    aws_issue["gateway_logging_enable"]
}

gateway_logging_enable_metadata := {
    "Policy Code": "PR-AWS-CFR-AG-004",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure that API Gateway has enabled access logging",
    "Policy Description": "Enabling the custom access logging option in API Gateway allows delivery of custom logs to CloudWatch Logs, which can be analyzed using CloudWatch Logs Insights. Using custom domain names in Amazon API Gateway allows insights into requests sent to each custom domain name.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-apigateway-stage.html"
}



#
# PR-AWS-CFR-AG-005
#

default gateway_tracing_enable = null

aws_issue["gateway_tracing_enable"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::apigateway::stage"
    not resource.Properties.TracingEnabled
}

source_path[{"gateway_tracing_enable": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::apigateway::stage"
    not resource.Properties.TracingEnabled
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "TracingEnabled"]
        ],
    }
}

aws_issue["gateway_tracing_enable"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::apigateway::stage"
    lower(resource.Properties.TracingEnabled) != "true"
}

source_path[{"gateway_tracing_enable": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::apigateway::stage"
    lower(resource.Properties.TracingEnabled) != "true"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "TracingEnabled"]
        ],
    }
}

gateway_tracing_enable {
    lower(input.Resources[i].Type) == "aws::apigateway::stage"
    not aws_issue["gateway_tracing_enable"]
}

gateway_tracing_enable = false {
    aws_issue["gateway_tracing_enable"]
}

gateway_tracing_enable_err = "Ensure API Gateway has tracing enabled" {
    aws_issue["gateway_tracing_enable"]
}

gateway_tracing_enable_metadata := {
    "Policy Code": "PR-AWS-CFR-AG-005",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure API Gateway has tracing enabled",
    "Policy Description": "With tracing enabled X-Ray can provide an end-to-end view of an entire HTTP request. You can use this to analyze latencies in APIs and their backend services",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-apigateway-stage.html"
}


#
# PR-AWS-CFR-AG-006
#

default gateway_method_public_access = null

aws_issue["gateway_method_public_access"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::apigateway::method"
    not resource.Properties.AuthorizationType
    not resource.Properties.ApiKeyRequired
}

source_path[{"gateway_method_public_access": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::apigateway::method"
    not resource.Properties.AuthorizationType
    not resource.Properties.ApiKeyRequired
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "ApiKeyRequired"]
        ],
    }
}

aws_issue["gateway_method_public_access"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::apigateway::method"
    lower(resource.Properties.AuthorizationType) == "none"
    not resource.Properties.ApiKeyRequired
}

source_path[{"gateway_method_public_access": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::apigateway::method"
    lower(resource.Properties.AuthorizationType) == "none"
    not resource.Properties.ApiKeyRequired
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "ApiKeyRequired"]
        ],
    }
}

aws_issue["gateway_method_public_access"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::apigateway::method"
    resource.Properties.AuthorizationType == null
    not resource.Properties.ApiKeyRequired
}

source_path[{"gateway_method_public_access": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::apigateway::method"
    resource.Properties.AuthorizationType == null
    not resource.Properties.ApiKeyRequired
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "ApiKeyRequired"]
        ],
    }
}

aws_issue["gateway_method_public_access"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::apigateway::method"
    not resource.Properties.AuthorizationType
    lower(resource.Properties.ApiKeyRequired) != "true"
}

source_path[{"gateway_method_public_access": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::apigateway::method"
    not resource.Properties.AuthorizationType
    lower(resource.Properties.ApiKeyRequired) != "true"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "ApiKeyRequired"]
        ],
    }
}

aws_issue["gateway_method_public_access"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::apigateway::method"
    lower(resource.Properties.AuthorizationType) == "none"
    lower(resource.Properties.ApiKeyRequired) != "true"
}

source_path[{"gateway_method_public_access": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::apigateway::method"
    lower(resource.Properties.AuthorizationType) == "none"
    lower(resource.Properties.ApiKeyRequired) != "true"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "ApiKeyRequired"]
        ],
    }
}

aws_issue["gateway_method_public_access"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::apigateway::method"
    resource.Properties.AuthorizationType == null
    lower(resource.Properties.ApiKeyRequired) != "true"
}

source_path[{"gateway_method_public_access": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::apigateway::method"
    resource.Properties.AuthorizationType == null
    lower(resource.Properties.ApiKeyRequired) != "true"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "ApiKeyRequired"]
        ],
    }
}

gateway_method_public_access {
    lower(input.Resources[i].Type) == "aws::apigateway::method"
    not aws_issue["gateway_method_public_access"]
}

gateway_method_public_access = false {
    aws_issue["gateway_method_public_access"]
}

gateway_method_public_access_err = "Ensure API gateway methods are not publicly accessible" {
    aws_issue["gateway_method_public_access"]
}

gateway_method_public_access_metadata := {
    "Policy Code": "PR-AWS-CFR-AG-006",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure API gateway methods are not publicly accessible",
    "Policy Description": "We recommend you configure a custom authorizer OR an API key for every method in the API Gateway.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-apigateway-method.html#cfn-apigateway-method-authorizationtype"
}

#
# PR-AWS-CFR-AG-007
#

default api_gw_cert = null

aws_issue["api_gw_cert"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::apigateway::stage"
    not resource.Properties.ClientCertificateId
}

source_path[{"api_gw_cert": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::apigateway::stage"
    not resource.Properties.ClientCertificateId
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "ClientCertificateId"]
        ],
    }
}

aws_issue["api_gw_cert"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::apigateway::stage"
    count(resource.Properties.ClientCertificateId) == 0
}

source_path[{"api_gw_cert": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::apigateway::stage"
    count(resource.Properties.ClientCertificateId) == 0
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "ClientCertificateId"]
        ],
    }
}

api_gw_cert {
    lower(input.Resources[i].Type) == "aws::apigateway::stage"
    not aws_issue["api_gw_cert"]
}

api_gw_cert = false {
    aws_issue["api_gw_cert"]
}

api_gw_cert_err = "AWS API Gateway endpoints without client certificate authentication" {
    aws_issue["api_gw_cert"]
}

api_gw_cert_metadata := {
    "Policy Code": "PR-AWS-CFR-AG-007",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS API Gateway endpoints without client certificate authentication",
    "Policy Description": "API Gateway can generate an SSL certificate and use its public key in the backend to verify that HTTP requests to your backend system are from API Gateway. This allows your HTTP backend to control and accept only requests originating from Amazon API Gateway, even if the backend is publicly accessible._x005F_x000D_ _x005F_x000D_ Note: Some backend servers may not support SSL client authentication as API Gateway does and could return an SSL certificate error. For a list of incompatible backend servers, see Known Issues. https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-known-issues.html",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-apigateway-stage.html"
}

#
# PR-AWS-CFR-AG-008
#

default api_gateway_not_configured_with_firewall_v2 = null

aws_issue["api_gateway_not_configured_with_firewall_v2"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::apigateway::stage"
    output := resource.Name
    count([c | contains(lower(input.Resources[j].Properties.ResourceArn.Ref), output); c:=1 ]) == 0
}

aws_issue["api_gateway_not_configured_with_firewall_v2"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::apigateway::stage"
    output := resource.Name
    count([c | contains(lower(input.Resources[j].Properties.ResourceArn.Ref), output); c:=1 ]) == 0
    lower(input.Resources[j].Type) == "aws::wafregional::webaclassociation" 
    not input.Resources[j].Properties.WebACLId
}

aws_issue["api_gateway_not_configured_with_firewall_v2"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::apigateway::stage"
    output := resource.Name
    count([c | contains(lower(input.Resources[j].Properties.ResourceArn.Ref), output); c:=1 ]) == 0
    lower(input.Resources[j].Type) == "aws::wafregional::webaclassociation" 
    count(input.Resources[j].Properties.WebACLId) == 0
}

aws_issue["api_gateway_not_configured_with_firewall_v2"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::apigateway::stage"
    output := resource.Name
    count([c | contains(lower(input.Resources[j].Properties.ResourceArn.Ref), output); c:=1 ]) == 0
    lower(input.Resources[j].Type) == "aws::wafregional::webaclassociation" 
    input.Resources[j].Properties.WebACLId == null
}

api_gateway_not_configured_with_firewall_v2 {
    lower(input.Resources[i].Type) == "aws::apigateway::stage"
    not aws_issue["api_gateway_not_configured_with_firewall_v2"]
}

api_gateway_not_configured_with_firewall_v2 = false {
    aws_issue["api_gateway_not_configured_with_firewall_v2"]
}

api_gateway_not_configured_with_firewall_v2_err = "AWS API Gateway REST API is not configured with AWS Web Application Firewall v2 (AWS WAFv2)" {
    aws_issue["api_gateway_not_configured_with_firewall_v2"]
}

api_gateway_not_configured_with_firewall_v2_metadata := {
    "Policy Code": "PR-AWS-CFR-AG-008",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud Formation",
    "Policy Title": "AWS API Gateway REST API is not configured with AWS Web Application Firewall v2 (AWS WAFv2)",
    "Policy Description": "AWS API Gateway REST API which is not configured with AWS Web Application Firewall. As a best practice, enable the AWS WAF service on API Gateway REST API to protect against application layer attacks. To block malicious requests to your API Gateway REST API, define the block criteria in the WAF web access control list (web ACL).",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-apigateway-stage.html"
}

#
# PR-AWS-CFR-AG-009
#

default api_gateway_uses_specific_tls_version = null

aws_issue["api_gateway_uses_specific_tls_version"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::apigateway::domainname"
    resource.Properties.SecurityPolicy != "TLS_1_2"
}

api_gateway_uses_specific_tls_version {
    lower(input.Resources[i].Type) == "aws::apigateway::domainname"
    not aws_issue["api_gateway_uses_specific_tls_version"]
}

api_gateway_uses_specific_tls_version = false {
    aws_issue["api_gateway_uses_specific_tls_version"]
}

api_gateway_uses_specific_tls_version_err = "Ensure AWS API Gateway uses TLS 1.2 in transit" {
    aws_issue["api_gateway_uses_specific_tls_version"]
}

api_gateway_uses_specific_tls_version_metadata := {
    "Policy Code": "PR-AWS-CFR-AG-009",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud Formation",
    "Policy Title": "Ensure AWS API Gateway uses TLS 1.2 in transit",
    "Policy Description": "It identifies if data is encrypted in transit using TLS1.2 for the traffic that API gateway sends.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-apigateway-domainname.html#cfn-apigateway-domainname-securitypolicy"
}

#
# PR-AWS-CFR-AG-010
#

default api_gateway_content_encoding_is_enabled = null

aws_issue["api_gateway_content_encoding_is_enabled"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::apigateway::restapi"
    not resource.Properties.MinimumCompressionSize
}

api_gateway_content_encoding_is_enabled {
    lower(input.Resources[i].Type) == "aws::apigateway::restapi"
    not aws_issue["api_gateway_content_encoding_is_enabled"]
}

api_gateway_content_encoding_is_enabled = false {
    aws_issue["api_gateway_content_encoding_is_enabled"]
}

api_gateway_content_encoding_is_enabled_err = "Ensure content encoding is enabled for API Gateway." {
    aws_issue["api_gateway_content_encoding_is_enabled"]
}

api_gateway_content_encoding_is_enabled_metadata := {
    "Policy Code": "PR-AWS-CFR-AG-010",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud Formation",
    "Policy Title": "Ensure content encoding is enabled for API Gateway.",
    "Policy Description": "It checks if API Gateway allows client to call API with compressed payloads by using one of the supported content codings. This is useful in cases where you need to compress the method response payload.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-apigateway-restapi.html#cfn-apigateway-restapi-minimumcompressionsize"
}
