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




    # Default IO packet size.
    DEFAULT_PACKET_SIZE = 2048
    # Default timeout for write operations
    DEFAULT_WRITE_TIMEOUT = 10
    # Default timeout for read operations
    DEFAULT_READ_TIMEOUT = 10
    # Default timeout waiting for error response at the end of message send.
    DEFAULT_READ_TAIL_TIMEOUT = 1
    
            It is a good idea to keep your ``packet_size`` close to MTU for
            better networking performance. However, if large packet fails
            without any feedback from APNs, then all device tokens in the
            packet will be considered to have failed.

            The ``tail_timeout`` argument defines the amount of time to wait
            for arrival of an error frame. APNs protocol does not define
            a *success* message, so in order to be sure the batch was
            successfully processed, we have to wait for any response at the end
            of :func:`send`. Any send will take time needed for sending
            everything plus ``tail_timeout``. Blame Apple for this.

            .. warning::
                If you set ``tail_timeout`` to low and your network is slow, then
                this client will not have the opportunity to receive the status
                frame in case of an error while sending the last bit of the batch.
                Yet again, blame Apple for this.
        
            :Arguments:
                - `packet_size` (int): minimum size of IO buffer in bytes.
                - `tail_timeout` (float): timeout for the final read in seconds.



            .. note::
                On any IO/SSL error this method will simply stop iterating and
                will close the connection. There is nothing you can do in case
                of an error. Just let it fail, next time you will fetch the
                rest of the failed tokens.















import time
import socket
import datetime
import select
import logging
from struct import unpack

# python 3 support
import six
import binascii

import OpenSSL

try:
    import threading as _threading
except ImportError:
    import dummy_threading as _threading

# module level logger
LOG = logging.getLogger(__name__)


class Backend(object):
    """ """
    # Default IO packet size.
    DEFAULT_WRITE_BUFFER_SIZE = 2048
    # Default timeout for write operations
    DEFAULT_WRITE_TIMEOUT = 10
    # 
    DEFAULT_READ_BUFFER_SIZE = 2048
    # Default timeout for read operations
    DEFAULT_READ_TIMEOUT = 10
    # Default timeout waiting for error response at the end of message send.
    DEFAULT_READ_TAIL_TIMEOUT = 1

    def __init__(self, write_buffer_size=DEFAULT_WRITE_BUFFER_SIZE,
                       write_timeout=DEFAULT_WRITE_TIMEOUT,
                       read_buffer_size=DEFAULT_READ_BUFFER_SIZE,
                       read_timeout=DEFAULT_READ_TIMEOUT,
                       read_tail_timeout=DEFAULT_READ_TAIL_TIMEOUT):
        """ """
        pass

    def get_write_buffer_size(self, connection):
        """ """
        return self.write_buffer_size

    def get_cached_connection(self, address, certificate):
        """ """
        # (address, certificate) is the key
        # lock on pool
        # lookup connection by key:
        #   - pick the first connection if found, remove from the pool
        #   - otherwise: get_new_connection()
        pass

    def release(self, connection):
        """ """
        # if connection is not closed, return to the pool for connection.key
        pass

    def get_new_connection(self, address, certificate):
        """ """
        # create new connection and add to the total list
        pass

    def closed(self, connection):
        """ """
        # assert connection is closed
        # remove from the total list

    def outdate(self, delta):
        """ Close open connections that are not used in more than ``delta`` time.

            You may call this method in a separate thread or run it in some
            periodic task. If you don't, then all connections will remain open
            until session is shut down. It might be an issue if you care about
            your open server connections.

            :Arguments:
                `delta` (``timedelta``): maximum age of unused connection.

            :Returns:
                Number of closed connections.
        """
        # no need to lock _connections, Python GIL will ensures exclusive access
        to_check = self._connections.values()

        # any new connection added to _connections in parallel are assumed to be
        # within delta.
        ret = 0
        for con in to_check:
            if con.try_acquire():
                try:
                    if not con.is_closed() and con.is_outdated(delta):
                        con.close()
                        ret += 1
                finally:
                    con.release()

        return ret

    def shutdown(self):
        pass


class Connection(object):
    """ Connection to APNs. """
    # How much of timeout to wait extra if we have some bytes from APNs, but
    # not enough for complete response. Trade-off between realtimeness and
    # not loosing response from APNs over slow network.
    extra_wait_factor = 0.5

    cant_detect_close = True

    #@property
    #is_closed

    #read_available() -> bytes
    #write(chunk) -> result
    #read(buffsize, timeout) -> bytes
    #close()

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
        self._address = address
        self._certificate = certificate
        self._socket = None
        self._connection = None
        self._readbuf = six.b("")
        self.__feedbackbuf = six.b("")
        self._last_refresh = None

    def is_outdated(self, delta):
        """ Returns True if this connection has not been refreshed in last delta time. """
        if self._last_refresh:
            return (datetime.datetime.now() - self._last_refresh) > delta

        return False

    def __del__(self):
        self.close()

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
                # just to be sure. maybe we shall also call self._cocket.shutdown()
                self._socket.close()
            except:
                pass

            self._socket = None
            self._connection = None
            self._readbuf = six.b("")
            self._feedbackbuf = six.b("")

    def is_closed(self):
        """ Returns True if this connection is closed.

            .. note:
                If other end closes connection by itself, then this connection will
                report open until next IO operation.
        """
        return self._socket is None

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

    def _ensure_socket_open(self):
        """ Refreshes socket. Hook that you may override. """
        if self._socket is None:
            try:
                self._socket = self._create_socket()
                self.configure_socket()
                self._connection = self._create_openssl_connection()
                self.configure_connection()
                self._connect_and_handshake()
            except Exception:
                self.close()
                raise

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

    def feedback(self, buffsize, timeout):
        """ Read and parse feedback information. """
        if self.is_closed():
            return None

        data = self.recv(buffsize, timeout)
        if data is not None:
            self._feed_feedback(data)
            return self._read_feedback()

        # timeout or connection closed
        return None

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

    def _feed(self, data):
        self._readbuf += data

    def _response(self):
        if len(self._readbuf) >= 6:
            ret = unpack(">BBI", self._readbuf[0:6])
            self._readbuf = self._readbuf[6:]

            if ret[0] != 8:
                raise ValueError("Got unknown command from APNs. Looks like protocol has been changed.")

            return (ret[1], ret[2])

        return None

    def _feed_feedback(self, data):
        self._feedbackbuf += data

    def _read_feedback(self):
        # FIXME: not the most efficient way to parse stream =)
        while len(self._feedbackbuf) > 6:
            timestamp, length = unpack(">IH", self._feedbackbuf[0:6])
            if len(self._feedbackbuf) >= (6 + length):
                token = binascii.hexlify(self._feedbackbuf[6:(length + 6)]).upper()
                self._feedbackbuf = self._feedbackbuf[(length + 6):]
                yield (token, timestamp)
            else:
                break
