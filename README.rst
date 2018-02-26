===================
Seed Message Sender
===================

Sends and receives messages between seed services and Vumi HTTP API

Channel configuration
---------------------

Concurrency Limiter Fields:
^^^^^^^^^^^^^^^^^^^^^^^^^^^

* **concurrency_limit**: A value of 0 disables concurrency limiter
* **message_delay**: Seconds to wait before retrying a waiting message
* **message_timeout**: Seconds until we assume a message has finished

Configuration:
^^^^^^^^^^^^^^

JSON field containing the following data:

Generic API:
""""""""""""

* **HTTP_API_URL**: http://example.com/
* **HTTP_API_AUTH**: ('username', 'password')
* **HTTP_API_FROM**: +4321
* **OVERRIDE_PAYLOAD**: {'new_key': 'key_from_original_payload'}
* **STRIP_FILEPATH**: True/False - True when voice files are hosted where the API is.

Original Payload::

    {
        "to": "+27820000000",
        "from": "1444",
        "content": "Hey, this is a message!",
        "channel_data": {
            "voice": {
                "speech_url": "http://sbm.com/hello.mp3"
            }
        }
    }

Example of OVERRIDE_PAYLOAD::

    {
        "to_msisdn": "to",
        "from_number": "from",
        "text": "content",
        "filename": "channel_data.voice.speech_url"
    }

Will generate this payload::

    {
        "to_msisdn": "+27820000000",
        "from_number": "1444",
        "text": "Hey, this is a message!",
        "filename": "http://sbm.com/hello.mp3"
    }


Junebug:
""""""""

* **JUNEBUG_API_URL**: http://example.com/
* **JUNEBUG_API_AUTH**: ('username', 'password')
* **JUNEBUG_API_FROM**: +4321

Vumi:
"""""

* **VUMI_CONVERSATION_KEY**: conv-key
* **VUMI_ACCOUNT_KEY**: account-key
* **VUMI_ACCOUNT_TOKEN**: account-token
* **VUMI_API_URL**: http://example.com/
