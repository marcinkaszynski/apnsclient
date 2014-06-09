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
import binascii
import datetime
from struct import unpack

# python 3 support
import six

__all__ = ('Session', 'Connection')

# module level logger
LOG = logging.getLogger(__name__)


class Session(object):
    """ The front-end for the underlying connection pool. """
    # Default APNs addresses.
    ADDRESSES = {
        "push_sandbox": ("gateway.sandbox.push.apple.com", 2195),
        "push_production": ("gateway.push.apple.com", 2195),
        "feedback_sandbox": ("feedback.sandbox.push.apple.com", 2196),
        "feedback_production": ("feedback.push.apple.com", 2196),
    }
    # Default write buffer size. Should be close to MTU size.
    DEFAULT_WRITE_BUFFER_SIZE = 2048
    # Default timeout for write operations.
    DEFAULT_WRITE_TIMEOUT = 10
    # Default read buffer size, used by feedback.
    DEFAULT_READ_BUFFER_SIZE = 2048
    # Default timeout for read operations.
    DEFAULT_READ_TIMEOUT = 10
    # Default timeout waiting for error response at the end message send operation.
    DEFAULT_READ_TAIL_TIMEOUT = 1
    
    def __init__(self, pool="apnsclient.backends.stdio",
                       write_buffer_size=DEFAULT_WRITE_BUFFER_SIZE,
                       write_timeout=DEFAULT_WRITE_TIMEOUT,
                       read_buffer_size=DEFAULT_READ_BUFFER_SIZE,
                       read_timeout=DEFAULT_READ_TIMEOUT,
                       read_tail_timeout=DEFAULT_READ_TAIL_TIMEOUT,
                       **pool_options):
        """ The front-end to the underlying connection pool. The purpose of this
            class is to hide the transport implementation that is being used for
            networking. Default implementation uses built-in python sockets and
            ``select`` for asynchronous IO.

            :Arguments:
                - pool (str, type or object): networking layer implementation.
                - write_buffer_size (int): chunk size for sending the message.
                - write_timeout (float): maximum time to send single chunk in seconds.
                - read_buffer_size (int): feedback buffer size for reading.
                - read_timeout (float): timeout for reading single feedback block.
                - read_tail_timeout (float): timeout for reading status frame after message is sent.
                - pool_options (kwargs): passed as-is to the pool class on instantiation.
        """
        # IO deafults
        self.write_buffer_size = write_buffer_size
        self.write_timeout = write_timeout
        self.read_buffer_size = read_buffer_size
        self.read_timeout = read_timeout
        self.read_tail_timeout = read_tail_timeout

        # class name given by qualified name
        if isinstance(pool, six.string_types):
            pool_module = __import__(pool)
            for name in pool.split('.')[1:]:
                try:
                    pool_module = getattr(pool_module, name)
                except AttributeError:
                    raise ImportError("Can't load pool backend", pool)

            try:
                pool = getattr(pool_module, "Backend")
            except AttributeError:
                raise ImportError("Can't find Backend class in pool module", pool)

        # resolved or given as class
        if isinstance(pool, type):
            pool = pool(**pool_options)

        self.pool = pool
        if LOG.isEnabledFor(logging.DEBUG):
            LOG.debug("New session, WB: %sb/%ss, RB: %sb/%ss, TT: %ss, Pool: %s",
                      write_buffer_size, write_timeout,
                      read_buffer_size, read_timeout,
                      read_tail_timeout,
                      pool.__class__.__module__)

    def get_address(cls, address):
        """ Maps address to (host, port) tuple. """
        if not isinstance(address, (list, tuple)):
            addr = cls.ADDRESSES.get(address)
            if addr is None:
                raise ValueError("Unknown address mapping: {0}".format(address))

            address = addr
        return address

    def get_certificate(self, cert_params):
        """ Create/load certificate from parameters. """
        # don't require pyOpenSSL by default, opening room for alternative implementations.
        from .certificate import Certificate
        return Certificate(**cert_params)

    def new_connection(self, address="feedback_sandbox", certificate=None, **cert_params):
        """ Obtain new connection to APNs. This method will not re-use existing
            connection from the pool. The connection will be closed after use.
            
            Unlike :func:`get_connection` this method does not cache the
            connection.  Use it to fetch feedback from APNs and then close when
            you are done.

            :Arguments:
                - address (str or tuple): target address.
                - certificate (:class:`Certificate`): provider's certificate instance.
                - cert_params (kwargs): :class:`Certificate` arguments, used if ``certificate`` instance is not given.
        """
        if certificate is not None:
            cert = certificate
        else:
            cert = self.get_certificate(cert_params)

        address = self.get_address(address)
        return Connection(address, cert, self, use_cache=False)

    def get_connection(self, address="push_sanbox", certificate=None, **cert_params):
        """ Obtain cached connection to APNs.

            Session caches connection descriptors, that remain open after use.
            Caching saves SSL handshaking time. Handshaking is lazy, it will be
            performed on first message send.

            You can provide APNs address as ``(hostname, port)`` tuple or as
            one of the strings:

                - push_sanbox -- ``("gateway.sandbox.push.apple.com", 2195)``, the default.
                - push_production -- ``("gateway.push.apple.com", 2195)``
                - feedback_sandbox -- ``("gateway.push.apple.com", 2196)``
                - feedback_production -- ``("gateway.sandbox.push.apple.com", 2196)``

            :Arguments:
                - address (str or tuple): target address.
                - certificate (:class:`Certificate`): provider's certificate instance.
                - cert_params (kwargs): :class:`Certificate` arguments, used if ``certificate`` instance is not given.
        """
        if certificate is not None:
            cert = certificate
        else:
            cert = self.get_certificate(cert_params)

        address = self.get_address(address)
        return Connection(address, cert, self, use_cache=True)

    def outdate(self, delta):
        """ Close open connections that are not used in more than ``delta`` time.

            You may call this method in a separate thread or run it in some
            periodic task. If you don't, then all connections will remain open
            until session is shut down. It might be an issue if you care about
            your open server connections.

            :Arguments:
                delta (``timedelta``): maximum age of unused connection.
        """
        if LOG.isEnabledFor(logging.DEBUG):
            if delta.total_seconds() == 0.0:
                LOG.debug("Shutdown session")
            else:
                LOG.debug("Outdating session with delta: %s", delta)

        self.pool.outdate(delta)

    def shutdown(self):
        """ Shutdown all connections in the pool. This method does will not close
            connections being use at the calling time.
        """
        self.pool.outdate(datetime.timedelta())

    def __del__(self):
        """ Last chance to shutdown() """
        self.shutdown()


class Connection(object):
    """ Connection wrapper. """

    def __init__(self, address, certificate, session, use_cache=False):
        """ New connection wrapper.
            
            :Arguments:
                - address (tuple) - (host, port) to connect to.
                - certificate (:class:Certificate) - provider certificate.
                - session (object) - parent session.
                - use_cache (bool) - True if connections may be cached in the pool.
        """
        self.address = address
        self.certificate = certificate
        self.session = session
        self.use_cache = use_cache
        self._reused = False
        self._connection = None
        self._lock = self._create_lock()

    def _create_lock(self):
        """ Provides semaphore with ``threading.Lock`` interface. """
        try:
            # can be monkey patched by gevent/greenlet/etc or can be overriden
            # entirely. The lock has to support .acquire() and .release() calls
            # with standard semantics.
            import threading as _threading
        except ImportError:
            import dummy_threading as _threading

        return _threading.Lock()

    def __enter__(self):
        try:
            if LOG.isEnabledFor(logging.DEBUG):
                LOG.debug("Entering networking session")

            self._lock.acquire() # block until lock is given
            self._open_connection()
        except:
            if LOG.isEnabledFor(logging.DEBUG):
                LOG.debug("Failed to enter networking session to address: %r", self.address, exc_info=True)

            self._lock.release()
            raise

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            if LOG.isEnabledFor(logging.DEBUG):
                LOG.debug("Leaving networking session%s%s",
                          " with still open connection" if self._connection else "",
                          " because of failure" if exc_type else "",
                          exc_info=(exc_type is not None))

            if self._connection:
                # terminate connection in case of an error
                self._close(terminate=exc_type is not None)
        finally:
            self._lock.release()

    def send(self, message):
        """ Send message. """
        with self:
            if not self._connection:
                if LOG.isEnabledFor(logging.INFO):
                    LOG.info("Failed to obtain message connection to address %r", self.address)
                # general error from the first token
                return (255, 0)

            batch = message.batch(self.session.write_buffer_size)
            failed_after = None
            first = True
            decoder = ResponseDecoder()
            status = None
            total_sent = 0
            for sent, chunk in batch:
                assert len(chunk) > 0
                total_sent += len(chunk)

                if first:
                    # first IO, that may trigger connection reinitialization
                    ret = self._ensuring_io(lambda con: con.write(chunk, self.session.write_timeout))
                    first = False
                else:
                    # other writes, that fail naturally
                    ret = self._connection.write(chunk, self.session.write_timeout)

                if ret is None:
                    # socket is closed, check what happened
                    failed_after = sent
                    break

                # non-blocking read
                ret = self._connection.read(256, 0) # status frame is 6 bytes
                if ret is not None:
                    decoder.feed(ret)
                    # NOTE: status can be overriden on status.code == 0 :: No errors
                    # because we got successframe without finishing all frames.
                    # Looks like connection was reused and this is left over from
                    # other session.
                    if status is not None:
                        LOG.warning("Got success frame while batch is not comleted. Frame ignored.")

                    status = decoder.decode()
                    if status is not None and status[0] != 0: # No errors encountered
                        if LOG.isEnabledFor(logging.INFO):
                            LOG.info("Message send failed midway with status %r to address %r. Sent successful tokens: %s, bytes: %s",
                                     status, self.address, sent, total_sent)

                        # some shit had happened, response from APNs, bail out and prepare for retry
                        self._close(terminate=True)
                        return status
                # else: no status frame is read, keep sending

            # status, only success or None.
            # status frame not yet received, blocking read for at most tail_timeout
            if status is None:
                ret = self._connection.read(256, self.session.read_tail_timeout)
                if ret:
                    decoder.feed(ret)
                    status = decoder.decode()
                    if status is not None and status[0] != 0:
                        if LOG.isEnabledFor(logging.INFO):
                            LOG.info("Message send failed with status %r to address %r. Bytes sent: %s",
                                     status, self.address, total_sent)

                        # some shit had indeed happened
                        self._close(terminate=True)
                        return status
                # else: failed to read status frame, probably because of the timeout,
                # which means transaction is probably ended successfully. APNs sucks.

            # normall successs scenario with success frame provided.
            if failed_after is None and status is not None and status[0] == 0:
                return status

            # OK, we have nothing received from APNs, but maybe this is due to timeout.
            # Check if we were abrubtly stopped because connection was closed
            if failed_after is not None:
                if LOG.isEnabledFor(logging.INFO):
                    LOG.info("Message send failed midway with status %r to address %r. Sent successful tokens: %s, bytes: %s",
                             status, self.address, failed_after, total_sent)

                # unknown error happened, we assume everything after last successful
                # send can be retried. It does not hurt to ensure/close again.
                self._close(terminate=True)
                ret = (255, failed_after + 1)
                return ret

            # we have sent message to all target tokens and have waited for
            # tail_timeout for any error reponse to arrive. Nothing arrived and
            # we did not fail middle on the road, so according to Apple's
            # manual everything went OK. Still, this protocol sucks.
            if LOG.isEnabledFor(logging.DEBUG):
                LOG.debug("Message sent successfully to address %r. Sent tokens: %s, bytes: %s",
                         self.address, len(message.tokens), total_sent)

            self._close(terminate=not self._reused)
            return None

    def feedback(self):
        """ Read and parse feedback information. On failure stop iteration. """
        with self:
            if self._connection:
                # first frame, ensuring connection
                data = self._ensuring_io(lambda con: con.read(self.session.read_buffer_size, self.session.read_timeout))
                feedback = FeedbackDecoder()
                total_records = 0
                while data is not None:
                    feedback.feed(data)
                    # TODO: use yield from
                    for record in feedback.decoded():
                        total_records += 1
                        yield record

                    # read next chunk
                    data = self._connection.read(self.session.read_buffer_size, self.session.read_timeout)

                # there is no point to keep this connection open
                if LOG.isEnabledFor(logging.DEBUG):
                    LOG.debug("Feedback received %s records from address %r",
                             total_records, self.address)

                self._close(terminate=True)
            else:
                if LOG.isEnabledFor(logging.INFO):
                    LOG.info("Failed to obtain feedback connection to address %r", self.address)
                # stop iterating, could not obtain connection

    def _ensuring_io(self, func):
        """ Re-opens connection if read or write has failed. Used to re-initialize
            connections from the pool with a transport not supporting reliable
            socket closed condition.
        """
        ret = self._connection.reset()  # clear read and write buffers
        if ret:
            ret = func(self._connection) # perform IO, True or string on success, None on failure or timeout.

        if ret is None:
            # failed, either because of IO error (socket closed) or timeout.
            # if pool.can_detect_close is False and we are reusing the connection
            # from the cache pool, then it was probably already closed when we got it.
            # Re-get the connection from the pool again.
            if not self.session.pool.can_detect_close and self._reused:
                if LOG.isEnabledFor(logging.DEBUG):
                    LOG.debug("Re-ensuring connection to address %r", self.address)
                # we won't release it, ensure it is surely closed
                self._connection.close()
                self._open_connection(by_failure=True)
                if self.session.pool.use_cache_for_reconnects:
                    if LOG.isEnabledFor(logging.DEBUG):
                        LOG.debug("Re-connected using cached connection. IO-checking again: %r", self.address)
                    # if ensuring logic is asking for a new connection from the pool,
                    # then we have to re-ensure the connection.
                    return self._ensuring_io(func)
                else:
                    if LOG.isEnabledFor(logging.DEBUG):
                        LOG.debug("Re-connected using new connection. Issuing raw IO: %r", self.address)
                    # ensuring logic was forced to open a fresh connection, which
                    # is open by definition. If we fail, then this is a real failure.
                    return func(self._connection)
            else:
                if LOG.isEnabledFor(logging.DEBUG):
                    LOG.debug("IO failure to address %r. Not reconnecting.", self.address)
        # successful response or we can't reopen connection
        return ret

    def _open_connection(self, by_failure=False):
        """ Request new connection handle from underlying pool. """
        # use pool if caching is requested or we are ensuring connection with
        # cache enabled.
        if self.use_cache and (not by_failure or self.session.pool.use_cache_for_reconnects):
            if LOG.isEnabledFor(logging.DEBUG):
                LOG.debug("Open cached connection to %r%s.", self.address, " by failure" if by_failure else "")

            self._connection = self.session.pool.get_cached_connection(self.address, self.certificate)
            self._reused = True
        else:
            if LOG.isEnabledFor(logging.DEBUG):
                LOG.debug("Open new connection to %r%s.", self.address, " by failure" if by_failure else "")

            self._connection = self.session.pool.get_new_connection(self.address, self.certificate)
            self._reused = False

    def _close(self, terminate=False):
        """ Close connection. """
        assert self._connection is not None
        if terminate:
            self._connection.close()
        else:
            self.session.pool.release(self._connection)

        self._connection = None


# private
class ResponseDecoder(object):
    """ Response frame decoder. """
    # Response command byte
    COMMAND = 8

    def __init__(self):
        self._buf = []

    def feed(self, data):
        """ Feed next frame with data. """
        self._buf.append(data)

    def decode(self):
        """ Returns reconstructed response frame. """
        buf = six.binary_type().join(self._buf)
        if len(buf) >= 6:
            ret = unpack(">BBI", buf[0:6])
            self._buf = []
            if len(buf) > 6:
                # should normally not happen as there is always a single frame
                self._buf.append(buf[6:])

            assert ret[0] == self.COMMAND, "Got unknown command from APNs: {}. Looks like protocol has been changed.".format(ret[0])
            return (ret[1], ret[2])
        else:
            self._buf = [buf]

        return None


# private
class FeedbackDecoder(object):
    """ Feedback decoder. """

    def __init__(self):
        self._buf = []

    def feed(self, data):
        """ Feed next frame with raw data. """
        self._buf.append(data)

    def decoded(self):
        """ Returns generator over next set of decoded records. """
        buf = six.binary_type().join(self._buf)
        pos = 0
        while (pos + 6) < len(buf):
            timestamp, length = unpack(">IH", buf[pos:(pos + 6)])
            assert length > 0

            if (pos + 6 + length) <= len(buf):
                token = binascii.hexlify(buf[(pos + 6):(pos + 6 + length)])
                pos += 6 + length
                yield token, timestamp
                if pos == len(buf):
                    break
            else:
                break

        # consume everything except suffix
        self._buf=[buf[pos:]]
