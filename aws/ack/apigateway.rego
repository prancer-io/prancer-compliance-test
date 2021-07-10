package rule

# https://github.com/aws-controllers-k8s/apigatewayv2-controller

#
# PR-AWS-0002-ACK
#

default api_gw_cert = null

aws_issue["api_gw_cert"] {
    resource := input.Resources[i]
    lower(resource.kind) == "stage"
    not resource.spec.clientCertificateID
}

aws_issue["api_gw_cert"] {
    resource := input.Resources[i]
    lower(resource.kind) == "stage"
    lower(resource.spec.clientCertificateID) == "none"
}

api_gw_cert {
    lower(input.Resources[i].Type) == "stage"
    not aws_issue["api_gw_cert"]
}

api_gw_cert = false {
    aws_issue["api_gw_cert"]
}

api_gw_cert_err = "AWS API Gateway endpoints without client certificate authentication" {
    aws_issue["api_gw_cert"]
}

api_gw_cert_metadata := {
    "Policy Code": "PR-AWS-0002-ACK",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "ACK",
    "Policy Title": "AWS API Gateway endpoints without client certificate authentication",
    "Policy Description": "API Gateway can generate an SSL certificate and use its public key in the backend to verify that HTTP requests to your backend system are from API Gateway. This allows your HTTP backend to control and accept only requests originating from Amazon API Gateway, even if the backend is publicly accessible._x005F_x000D_ _x005F_x000D_ Note: Some backend servers may not support SSL client authentication as API Gateway does and could return an SSL certificate error. For a list of incompatible backend servers, see Known Issues. https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-known-issues.html",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-apigateway-stage.html"
}
