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

import time
import socket
import datetime
import select
import logging
import OpenSSL

# python 3 support
import six

from . import BaseBackend, BaseConnection


# module level logger
LOG = logging.getLogger(__name__)


class Backend(BaseBackend):
    """ """
    # no, we can't detect if socket is closed without IO
    can_detect_close = False

    def get_new_connection(self, address, certificate):
        """ Open a new connection.
        
            :Arguments:
                - address (tuple): target (host, port).
                - certificate (:class:Certificate): certificate instance.
        """
        raise Connection(address, certificate)


class Connection(BaseConnection):
    """ Connection to APNs. """

    def __init__(self, address, certificate):
        """ Connection to APNs.

            If your application is multi-threaded, then you have to lock this
            connection before changing anything. Simply use the connection as
            context manager in ``with`` statement. 

            .. note::
                You don't have to deal with locking at all if you just use
                :class:`APNs` methods. The connection is a low-level object,
                you may use it directly if you plan to configure it to your
                needs (eg. SSL verification) or manually manage its state.

            :Arguments:
                - `address` (tuple): address as (host, port) tuple.
                - `certificate` (:class:`Certificate`): provider's certificate.
        """
        super(Connection, self).__init__(address, certificate)
        self._open_connection()

    def _open_connection(self):
        """ Refreshes socket. Hook that you may override. """
        try:
            self._socket = self._create_socket()
            self.configure_socket()
            self._connection = self._create_openssl_connection()
            self.configure_connection()
            self._connect_and_handshake()
        except Exception:
            self.close()
            raise

    def _create_socket(self):
        """ Create new plain TCP socket. Hook that you may override. """
        return socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def configure_socket(self):
        """ Hook to configure socket parameters. """
        pass

    def _create_openssl_connection(self):
        """ Create new OpenSSL connection. Hook that you may override. """
        return OpenSSL.SSL.Connection(self._certificate.get_context(), self._socket)

    def configure_connection(self):
        """ Hookt to configure SSL connection. """
        pass

    def _connect_and_handshake(self):
        """ Connect to APNs and SSL handshake. Hook that you may override. """
        self._connection.connect(self._address)
        self._connection.do_handshake()






    def closed(self):
        """ Returns True if connection is closed via explicit ``close()`` call.
            If ``backend.can_detect_close`` is False, then this method is allowed
            to return False even if underlying connection has been closed by itself.
        """
        """ Returns True if this connection is closed.

            .. note:
                If other end closes connection by itself, then this connection will
                report open until next IO operation.
        """
        return self._socket is None

    def close(self):
        """ Close connection and free underlying resources. """
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
                # just to be sure. maybe we shall also call self._cocket.shutdown()
                self._socket.close()
            except:
                pass

            self._socket = None
            self._connection = None
            self._readbuf = six.b("")
            self._feedbackbuf = six.b("")

    def reset(self):
        """ Clear read and write buffers. Called before starting a new IO session. """
        raise NotImplementedError

    def write(self, data, timeout):
        """ Write chunk of data. Returns True`if data is completely written,
            otherwise returns None indicating IO failure or that timeout has
            been exceeded.
        """
        raise NotImplementedError

    def read(self, size, timeout):
        """ Reach chunk of data. Returns read bytes or None on any failure or if
            timeout is exceeded. If timeout is zero, then method is not allowed
            to block, but has to return data available in the read buffer or fail
            immediatelly.
        """
        raise NotImplementedError





















    def refresh(self):
        """ Ensure socket is still alive. Reopen if needed. """
        self._ensure_socket_open()
        self._readbuf = six.b("")
        self._feedbackbuf = six.b("")
        self._last_refresh = datetime.datetime.now()

    def send(self, chunk):
        """ Blocking write to SSL connection.

            :Returns:
                True if chunk is fully sent, False on failure
        """
        if self.is_closed():
            return False

        # blocking mode, never throw WantWriteError
        self._connection.setblocking(1)
        try:
            self._connection.sendall(chunk)
            return True
        except OpenSSL.SSL.Error:
            # underlying connection has been closed or failed
            self.close()
            return False

    def peek(self):
        """ Non blocking read for APNs result. """
        if self.is_closed():
            return None

        ret = self.recv(256, 0)
        if not ret:
            # closed or nothing to read without blocking
            return None

        self._feed(ret)
        return self._response()

    def pull(self, timeout):
        """ Blocking read for APNs result in at most timeout. """
        if self.is_closed():
            return None

        waited = 0
        towait = timeout
        while True:
            before = time.time()
            ret = self.recv(256, towait)
            if not ret:
                # closed or timed out. possibly with some previously read, but
                # incomplete response in the buffer. we assume APNs doesn't want to
                # say anything back. This is a *really bad* protocol Apple, you suck.
                return None

            waited += time.time() - before
            self._feed(ret)
            ret = self._response()
            if ret:
                # we got response, end quickly. This usually means nothing good
                # for you, developer =)
                return ret

            # OK, we got some bytes, but it is not enough for response. should
            # never happens since we expect to get at most 6 bytes back.
            if waited >= timeout:
                # there is something in read buffer, but we run out of time.
                # that response is much more important than real-timeness, so
                # lets wait a little more.
                towait = timeout * self.extra_wait_factor
                if towait == 0:
                    # looks like subclass has disabled extra_wait_factor
                    return None
            else:
                towait = timeout - waited

    def recv(self, buffsize, timeout=None):
        """ Read bytes from connection.

            Unlike standard socket, this method returns None if other end has
            closed the connection or no data has been received within timeout.
        """
        if self.is_closed():
            return None

        if timeout is not None:
            self._connection.setblocking(0)
        else:
            self._connection.setblocking(1)

        waited = 0
        while True:
            try:
                ret = self._connection.recv(buffsize)
                if ret or timeout is None:
                    if not ret:
                        # empty result on blocking read means socket is dead.
                        # should not happen, pyOpenSSL raises WantReadError instead.
                        # but just in case we handle it.
                        self.close()

                    return ret or None
            except OpenSSL.SSL.ZeroReturnError:
                # SSL protocol alerted close. We have a nice shutdown here.
                self.close()
                return None
            except OpenSSL.SSL.WantReadError:
                # blocking mode and there is not enough bytes read means socket
                # is abruptly closed (other end crashed)
                if timeout is None:
                    self.close()
                    return None

            if timeout == 0 or waited >= timeout:
                # no time left
                return None

            # so, we perform blocking read and there was not enough bytes.
            # note: errors is for out-of-band and other shit. not what you may
            # think an IO erro would be ;-)
            before = time.time()
            canread, _, _ = select.select((self._socket, ), (), (), timeout - waited)
            if not canread:
                # timeout elapsed without data becoming available, bail out
                return None

            waited += time.time() - before
