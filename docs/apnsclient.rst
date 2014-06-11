apnsclient Package
==================
`Apple Push Notification service
<https://developer.apple.com/library/mac/documentation/NetworkingInternet/Conceptual/RemoteNotificationsPG/Chapters/ApplePushService.html#//apple_ref/doc/uid/TP40008194-CH100-SW9>`_
client. Only public API is documented here to limit visual clutter. Refer to
`the sources <https://bitbucket.org/sardarnl/apns-client/>`_ if you want to
extend this library. Check :ref:`intro` for usage examples.


:mod:`apnsclient` Package
-------------------------

.. automodule:: apnsclient.transport

.. autoclass:: Session
    :members: new_connection, get_connection, outdate, shutdown

.. automodule:: apnsclient.apns

.. autoclass:: APNs
    :members: send, feedback

.. autoclass:: Message
    :members: tokens, __getstate__

.. autoclass:: Result
    :members: errors, failed, needs_retry, retry
