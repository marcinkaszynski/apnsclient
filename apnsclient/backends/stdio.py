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

from . import BaseBackend, BaseConnection

# module level logger
LOG = logging.getLogger(__name__)


class Connection(BaseConnection):
    """ Connection to APNs. """

    def __init__(self, address, certificate, timeout=None):
        """ Open new connection to APNs using POSIX sockets and pyOpenSSL.

            :Arguments:
                - address (tuple): address as (host, port) tuple.
                - certificate (:class:`Certificate`): provider's certificate.
                - timeout (float): connection timeout in seconds.
        """
        super(Connection, self).__init__(address, certificate, timeout=None)
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
            self._handshake()
            if LOG.isEnabledFor(logging.DEBUG):
                LOG.debug("SSL handshaking to %r completed", self.address)
        except:
            LOG.warning("Failed to establish socket/SSL connection to %r", self.address, exc_info=True)
            self.close()
            raise

    def _create_socket(self, timeout):
        """ Create new plain TCP socket. """
        return socket.create_connection(self.address, timeout)

    def _configure_socket(self):
        """ Hook to configure socket parameters. """
        pass

    def _create_openssl_connection(self):
        """ Create new OpenSSL connection. """
        return OpenSSL.SSL.Connection(self._certificate.get_context(), self._socket)

    def _configure_connection(self):
        """ Hookt to configure SSL connection. """
        pass

    def _handshake(self):
        """ Connect to APNs and SSL handshake. """
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
            return None

        self._connection.setblocking(1)
        self._socket.settimeout(timeout)
        try:
            self._connection.sendall(data)
        except OpenSSL.SSL.WantWriteError:
            LOG.warning("Write timeout %s it too short for buffer %s", timeout, len(data), exc_info=True)
            self.close()
            raise
        except:
            self.close()
            raise

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
                self.close()
                return None
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
