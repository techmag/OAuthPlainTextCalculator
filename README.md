# OAuthPlainTextCalculator
Scala (work-around) to handle APIs that use PLAINTEXT Oauth signing 

The Scala docs https://www.playframework.com/documentation/2.4.x/ScalaOAuth have an example for a Twitter API client with a segment that "signs" WS.urls with an OAuthCalculator 

This is a direct dropin replacement for any similar OAuth based API that needs PLAINTEXT signing.

Note: Some vendors use this with though that HTTPS would pretect them however be aware that PLAINTEXT is NOT actually signed! So use HMAC-SHA1 IF you can. 
