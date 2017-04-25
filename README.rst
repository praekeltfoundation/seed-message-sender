===================
Seed Message Sender
===================

Sends and receives messages between seed services and Vumi HTTP API


##Channel configuration

###Concurrency Limiter Fields:
**concurrency_limit**: A value of 0 disables concurrency limiter
**message_delay**: Seconds to wait before retrying a waiting message
**message_timeout**: Seconds until we assume a message has finished

###Configuration:
JSON field containing the following data:

Junebug:
**JUNEBUG_API_URL**: http://example.com/
**JUNEBUG_API_AUTH**: ('username', 'password')
**JUNEBUG_API_FROM**: +4321

Vumi:
**VUMI_CONVERSATION_KEY**: conv-key
**VUMI_ACCOUNT_KEY**: account-key
**VUMI_ACCOUNT_TOKEN**: account-token
**VUMI_API_URL**: http://example.com/
