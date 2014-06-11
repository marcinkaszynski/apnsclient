.. _intro:

Getting Started
===============

You will need `Apple's developer account
<https://developer.apple.com/support/registered/>`_. Then you have to obtain
your provider's certificate. The certificate must be in ``PEM`` format. You may
keep the private key with your certificate or in a separate file. Read `the
APNs manual
<https://developer.apple.com/library/mac/documentation/NetworkingInternet/Conceptual/RemoteNotificationsPG/Chapters/ApplePushService.html#//apple_ref/doc/uid/TP40008194-CH100-SW9>`_
to understand its architecture and all implications. This library hides most of
the complex mechanics behind APNs protocol, but some aspects, such as
constructing the payload or interpreting the error codes is left to you.

Usage
-----

If you don't mind to SSL handshake with APNs each time you send a batch of messages,
then use ``Session.new_connection()``. Otherwise, create a new session and keep
reference to it to prevent it being garbage collected. Example::

    from apnsclient import *

    # For feedback or non-intensive messaging
    con = Session().new_connection("feedback_sandbox", cert_file="sandbox.pem")

    # Persistent connection for intensive messaging.
    # Keep reference to session instance in some class static/global variable,
    # otherwise it will be garbage collected and all connections will be closed.
    session = Session()
    con = session.get_connection("push_sandbox", cert_file="sandbox.pem")


The connections you obtain from ``Session`` are lazy and will be really
established once you actually use it. Example of sending a message::

    # New message to 3 devices. You app will show badge 10 over app's icon.
    message = Message(["my", "device", "tokens"], alert="My message", badge=10)

    # Send the message.
    srv = APNs(con)
    try:
        res = srv.send(message)
    except:
        print "Can't connect to APNs, looks like network is down"
    else:
        # Check failures. Check codes in APNs reference docs.
        for token, reason in res.failed.items():
            code, errmsg = reason
            # according to APNs protocol the token reported here
            # is garbage (invalid or empty), stop using and remove it.
            print "Device failed: {0}, reason: {1}".format(token, errmsg)

        # Check failures not related to devices.
        for code, errmsg in res.errors:
            print "Error: {}".format(errmsg)

        # Check if there are tokens that can be retried
        if res.needs_retry():
            # repeat with retry_message or reschedule your task
            retry_message = res.retry()


APNs protocol is notoriously badly designed. It wasn't possible to detect which
message has been failed in a batch. Since last update, APNs supports enhanced
message format with possibility to detect `first failed message`. On detected
failure the ``retry()`` method will build a message with the rest of device
tokens, that you can retry. Unlike GCM, you may retry it right away without any
delay.

If you don't like to keep your cached connections open for too long, then close
them regularly. Example::

    import datetime

    # For how long may connections stay open unused
    delta = datetime.timedelta(minutes=5)

    # Close all connections that have not been used in the last delta time.
    # You may call this method at the end of your task or in a spearate periodic
    # task. If you use threads, you may call it in a spearate maintenance
    # thread.
    session.outdate(delta)

    # Shutdown session if you want to close all unused cached connections.
    # This call is equivalent to Session.outdate() with zero delta time.
    session.shutdown()

You have to regularly check feedback service for any invalid tokens. Schedule
it on some kind of periodic task. Any reported token should be removed from
your database, unless you know the token has been re-registered again.
Example::

    # feedback needs no persistent connections.
    con = Session().new_connection("feedback_sandbox", cert_file="sandbox.pem")
    srv = APNs(con)

    try:
        # on any IO failure after successfull connection this generator
        # will simply stop iterating. you will pick the rest of the tokens
        # during next feedback session.
        for token, when in service.feedback():
            # every time a devices sends you a token, you should store
            # {token: given_token, last_update: datetime.datetime.now()}
            last_update = get_last_update_of_token(token)

            if last_update < when:
                # the token wasn't updated after the failure has
                # been reported, so the token is invalid and you should
                # stop sending messages to it.
                remove_token(token)
    except:
        print "Can't connect to APNs, looks like network is down"


The ``APNs.feedback()`` may fail with IO errors, in this case the feedback
generator will simply end without any warning. Don't worry, you will just fetch
the rest of the feedback later. We follow here `let if fail` principle for much
simpler API.
