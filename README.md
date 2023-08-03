# Spring Security dual Authentication 
This application explores the possibility of using more than one mechanism for authentication in  a springboot application.
Different authentication mechanism was used in this application to access different resource end point. for this apllication both httpBasic and Json web token( JWT) was used for authentication.

## Motivation

This project is built on my last project where i secured a web resource using JWT. I have now in this project secured different endpoint with different mechanism

## How to use this Project
To use this project, a user must first be registered by supplying an email and a password. then depending on the resource to be accessed, you can use httpBasic for authentication or JWT.
You can test this application by using postMan.

This project  was built  by configuring two security filterchain where each filterchain handles a specific authentication mechanism.
The delegating filter delegates to a filterchain, requests based on the security matchers argument. 

## What is not included

As usual I have not written tests for this project.
