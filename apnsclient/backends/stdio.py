# Copyright 2014 Sardar Yumatov
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import socket
import OpenSSL

try:
    import threading as _threading
except ImportError:
    import dummy_threading as _threading

# python 3 support
import six

from . import BaseBackend, BaseConnection
from ..certificate import BaseCertificate

# module level logger
LOG = logging.getLogger(__name__)


class Certificate(BaseCertificate):
    """ pyOpenSSL certificate implementation. """

    def load_context(self, cert_string=None, cert_file=None, key_string=None, key_file=None, passphrase=None):
        """ Initialize and load certificate context. """
        context = OpenSSL.SSL.Context(OpenSSL.SSL.SSLv3_METHOD)
        if not isinstance(passphrase, six.binary_type):
            passphrase = six.b(passphrase)
        
        if cert_file:
            # we have to load certificate for equality check. there is no
            # other way to obtain certificate from context.
            if LOG.isEnabledFor(logging.DEBUG):
                LOG.debug("Certificate provided as file: %s", cert_file)

            with open(cert_file, 'rb') as fp:
                cert_string = fp.read()
        else:
            if LOG.isEnabledFor(logging.DEBUG):
                LOG.debug("Certificate provided as string")

        cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_string)
        context.use_certificate(cert)

        if not key_string and not key_file:
            if LOG.isEnabledFor(logging.DEBUG):
                LOG.debug("Private key provided with certificate %s %s passphrase",
                            'file' if cert_file else 'string',
                            'with' if passphrase is not None else 'without')

            # OpenSSL is smart enought to locate private key in the certificate
            args = [OpenSSL.crypto.FILETYPE_PEM, cert_string]
            if passphrase is not None:
                args.append(passphrase)

            pk = OpenSSL.crypto.load_privatekey(*args)
            context.use_privatekey(pk)
        elif key_file and passphrase is None:
            if LOG.isEnabledFor(logging.DEBUG):
                LOG.debug("Private key provided as file without passphrase: %s", key_file)

            context.use_privatekey_file(key_file, OpenSSL.crypto.FILETYPE_PEM)
        else:
            if key_file:
                if LOG.isEnabledFor(logging.DEBUG):
                    LOG.debug("Private key provided as file withpassphrase: %s", key_file)

                # key file is provided with passphrase. context.use_privatekey_file
                # does not use passphrase, so we have to load the key file manually.
                with open(key_file, 'rb') as fp:
                    key_string = fp.read()
            else:
                if LOG.isEnabledFor(logging.DEBUG):
                    LOG.debug("Private key provided as string % passphrase",
                                'with' if passphrase is not None else 'without')

            args = [OpenSSL.crypto.FILETYPE_PEM, key_string]
            if passphrase is not None:
                args.append(passphrase)

            pk = OpenSSL.crypto.load_privatekey(*args)
            context.use_privatekey(pk)

        # check if we are not passed some garbage
        context.check_privatekey()
        return context, cert

    def dump_certificate(self, raw_certificate):
        """ Dump certificate as PEM string.
        
            :Arguments:
                - context (object): certificate context as returned by :func:`load_context`

            :Returns:
                Certificate string as sequence of bytes.
        """
        return OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, raw_certificate)

    def dump_digest(self, raw_certificate, digest):
        """ Dump certificate digest.

            :Arguments:
                - context (object): certificate context as returned by :func:`load_context`
                - digest (str): digest name, such as "sha1"

            :Returns:
                Digest as sequence of bytes.
        """
        return raw_certificate.digest(digest)


class Connection(BaseConnection):
    """ Connection to APNs. """

    def __init__(self, address, certificate, timeout=None):
        """ Open new connection to APNs using POSIX sockets and pyOpenSSL.

            :Arguments:
                - address (tuple): address as (host, port) tuple.
                - certificate (:class:`Certificate`): provider's certificate.
                - timeout (float): connection timeout in seconds.
        """
        super(Connection, self).__init__(address, certificate)
        self._socket = None
        self._connection = None
        self._timeout = timeout
        self._open_connection(timeout)

    def _open_connection(self, timeout):
        """ Open remote connection. """
        try:
            if LOG.isEnabledFor(logging.DEBUG):
                LOG.debug("Opening POSIX socket/pyOpenSSL connection to %r", self.address)
            self._socket = self._create_socket(timeout)
            self._configure_socket()
            self._connection = self._create_openssl_connection()
            self._configure_connection()
            self._connect_and_handshake()
            if LOG.isEnabledFor(logging.DEBUG):
                LOG.debug("SSL handshaking to %r completed", self.address)
        except:
            LOG.warning("Failed to establish socket/SSL connection to %r", self.address, exc_info=True)
            self.close()
            raise

    def _create_socket(self, timeout):
        """ Create new plain TCP socket. """
        return socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def _configure_socket(self):
        """ Hook to configure socket parameters. """
        pass

    def _create_openssl_connection(self):
        """ Create new OpenSSL connection. """
        ctx = self.certificate.get_context()
        if self._timeout is not None:
            ctx.set_timeout(int(self._timeout))
        return OpenSSL.SSL.Connection(ctx, self._socket)

    def _configure_connection(self):
        """ Hookt to configure SSL connection. """
        pass

    def _connect_and_handshake(self):
        """ Connect to APNs and SSL handshake. """
        self._connection.connect(self.address)
        # NOTE: if we set any timeout on the underlying socket, then OpenSSL wrapper
        # will always immediately fail with WantReadError without even attempting
        # to block for that timeout. So we use an infinitelly blocking socket here,
        # but we have set timeout on context object and we hope it works.
        self._connection.setblocking(1)
        self._connection.do_handshake()

    def closed(self):
        """ Returns True if this connection is explicitly closed with :func:`close` call. """
        return self._socket is None

    def close(self):
        """ Close this connection. """
        if self._socket is not None:
            if self._connection is not None:
                try:
                    # tell SSL socket we are done
                    self._connection.shutdown()
                except:
                    pass
                try:
                    # free SSL related resources
                    self._connection.close()
                except:
                    pass

            try:
                # shutdown IO
                self._socket.shutdown()
            except:
                pass
            try:
                # close socket
                self._socket.close()
            except:
                pass

            self._socket = None
            self._connection = None

    def reset(self):
        """ Flushes read buffer. """
        to_skip = self._connection.pending()
        if to_skip > 0:
            self._connection.recv(to_skip)

    def write(self, data, timeout):
        """ Write chunk of data. """
        if self.closed():
            raise IOError("Connection is closed")

        # FIXME: pyOpenSSL can't block with the socket if timeout is set to
        # any value except None. So it is either block forewer or immediate
        # WantReadError without waiting at all. we have to use select() blocking
        
        
        self._connection.setblocking(1)
        self._socket.settimeout(timeout)
        try:
            self._connection.sendall(data)
        except OpenSSL.SSL.WantWriteError:
            LOG.warning("Write timeout %s it too short for buffer %s", timeout, len(data), exc_info=True)
            raise

    def peek(self, size):
        """ """
        pass

    def read(self, size, timeout):
        """ Read chunk of data. """
        if self.closed():
            return None

        if timeout == 0.0:
            self._connection.setblocking(0)
        else:
            self._connection.setblocking(1)

        self._socket.settimeout(timeout)
        while True:
            try:
                ret = self._connection.recv(size)
                if not ret:
                    # in case recv() responds with empty string on timeout.
                    return None
            except OpenSSL.SSL.ZeroReturnError:
                # SSL connection has been closed by protocol. socket might be still
                # open, so close everything.
                return True
            except OpenSSL.SSL.WantReadError:
                # we can't receive anything within timeout, fail with empty value
                return None
            except:
                self.close()
                raise


class Backend(BaseBackend):
    """ IO backend based on POSIX sockets. """
    # no, we can't detect if socket is closed without IO
    can_detect_close = False
    # raw connection implementation
    connection_class = Connection

    def get_new_connection(self, address, certificate, timeout=None):
        """ Open a new connection.
        
            :Arguments:
                - address (tuple): target (host, port).
                - certificate (:class:`Certificate`): certificate instance.
                - timeout (float): connection timeout in seconds
        """
        return self.connection_class(address, certificate, timeout=timeout)

    def get_certificate(self, cert_params):
        """ Create/load certificate from parameters. """
        return Certificate(**cert_params)

    def create_lock(self):
        """ Provides semaphore with ``threading.Lock`` interface. """
        return _threading.Lock()
