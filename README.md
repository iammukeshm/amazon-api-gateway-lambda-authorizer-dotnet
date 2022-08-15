# Securing Amazon API Gateway with Lambda Authorizer in .NET

In this article, we will learn about Securing Amazon API Gateway with Lambda Authorizer in .NET!

![Securing Amazon API Gateway with Lambda Authorizer in .NET](https://codewithmukesh.com/wp-content/uploads/2022/08/Amazon-API-Gateway-with-.NET_.png)

Lambda Authorizer is a component/feature of Amazon API Gateways that is responsible for Access to the protected resources of the API Gateway. The Lambda Authorizer is technically an AWS Lambda configured as an Authorizer while setting up the Amazon API Gateway. Lambda Authorizers are vital when you need to build a custom auth scheme. When a client would send a request to the Amazon API Gateway, internally the Gateway calls the attached Lambda Authorizer, which takes the token from the parameter/body, validates it, and returns an IAM policy/indication that the request is authorized or not.

Topics Covered:
- What’s a Lambda Authorizer in Amazon API Gateway?
- Getting started with Lambda Authorizer in .NET
- User Model
- Token Generation
- Token Validation – Lambda Authorizer
- Publish to AWS Lambda
- Integration & Testing

Read Article : https://codewithmukesh.com/blog/aws-lambda-authorizer-in-dotnet/
