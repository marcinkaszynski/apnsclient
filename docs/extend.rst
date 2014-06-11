.. _extend:

Extending the client
====================

The client is designed to be as generic as possible. Everything related to
transport layer is put together in pluggable back-ends. The default back-end is
``apnsclient.backends.stdio``. It is using raw python sockets for networking,
``select()`` for IO blocking and ``pyOpenSSL`` as SSL tunnel. The default
back-end will probably fail to work in ``gevent`` environment because
``pyOpenSSL`` works with POSIX file descriptors directly.

You can write your own back-end that will work in your preferred, probably
*green*, environment. Therefore you have to write the following classes.

``your.module.Certificate``
    SSL certificate instance using SSL library of your choice. Extends from
    ``apnsclient.certificate.BaseCertificate``. The class should implement the
    following methods:

    * ``load_context()`` - actual certificate loading from file or string.
    * ``dump_certificate()`` - dump certificate for equality check.
    * ``dump_digest()`` - dump certificate digest, such as ``sha1`` or ``md5``.

``your.module.Connection``
    SSL tunnel using IO and SSL library of your choice. Extends from
    ``apnsclient.backends.BaseConnection``. The class should implement the
    following methods:

    * ``reset()`` - flush read and write buffers before new transmission.
    * ``peek()`` - non-blocking read, returns bytes directly available in the read buffer.
    * ``read()`` - blocking read.
    * ``write()`` - blocking write.
    * ``close()`` - close underlying connection.
    * ``closed()`` - reports connection state.

``your.module.Backend``
    Factory class for certificates, thread locking and networking connections.
    Extends from ``apnsclient.backends.BaseBackend``. The class should
    implement the following methods:

    * ``get_certificate()`` - load certificate and returns your custom wrapper.
    * ``create_lock()`` - create ``theading.Lock`` like semaphore.
    * ``get_new_connection()`` - open ready to use SSL connection.


The main logic behind each of these classes is easy. The certificate is used as
a key in the connection pool, so it should support ``__eq__`` (equality)
operation. The equality check can be performed by comparing whole certificate
dump or just the digest if you don't like the idea to hold sensitive data in
python's memory for long. The connection implements basic IO operations. The
connection can be cached in the pool, so it is possible that some stale data
from a previous session will slip into the next session. The remedy is to flush
read an write buffers using ``Connection.reset()`` before sending a new
message. The back-end instance acts as a factory for your certificates, locks
and connections. The locking is dependent on your environment, you don't have
to monkey patch ``threading`` module therefore.

It is a good idea to look at the source code of the standard back-end
``apnsclient.backends.stdio`` and elaborate from that. Your back-end can be
supplied to the ``Session`` using fully qualified module name, as a class or as
an initialized instance. If you supply your back-end using module name, then
the name of your back-end class must be ``Backend``.

If you hit any trouble or if you think your back-end is worth sharing with
the rest of the world, then contact me `Sardar Yumatov <mailto:ja.doma@gmail.com>`_
or make an issue/pull-request on `APNs Bitbucket page
<https://bitbucket.org/sardarnl/apns-client/>`_.
