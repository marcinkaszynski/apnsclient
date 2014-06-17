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
    # Default timeout for attempting a new connection.
    DEFAULT_CONNECT_TIMEOUT = 10
    # Default write buffer size. Should be close to MTU size.
    DEFAULT_WRITE_BUFFER_SIZE = 2048
    # Default timeout for write operations.
    DEFAULT_WRITE_TIMEOUT = 20
    # Default read buffer size, used by feedback.
    DEFAULT_READ_BUFFER_SIZE = 2048
    # Default timeout for read operations.
    DEFAULT_READ_TIMEOUT = 20
    # Default timeout waiting for error response at the end message send operation.
    DEFAULT_READ_TAIL_TIMEOUT = 3
    
    def __init__(self, pool="apnsclient.backends.stdio",
                       connect_timeout=DEFAULT_CONNECT_TIMEOUT,
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
                - connect_timeout (float): timeout for new connections.
                - write_buffer_size (int): chunk size for sending the message.
                - write_timeout (float): maximum time to send single chunk in seconds.
                - read_buffer_size (int): feedback buffer size for reading.
                - read_timeout (float): timeout for reading single feedback block.
                - read_tail_timeout (float): timeout for reading status frame after message is sent.
                - pool_options (kwargs): passed as-is to the pool class on instantiation.
        """
        # IO deafults
        self.connect_timeout = connect_timeout
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

    @classmethod
    def get_address(cls, address):
        """ Maps address to (host, port) tuple. """
        if not isinstance(address, (list, tuple)):
            addr = cls.ADDRESSES.get(address)
            if addr is None:
                raise ValueError("Unknown address mapping: {0}".format(address))

            address = addr
        return address

    def new_connection(self, address="feedback_sandbox", certificate=None, **cert_params):
        """ Obtain new connection to APNs. This method will not re-use existing
            connection from the pool. The connection will be closed after use.
            
            Unlike :func:`get_connection` this method does not cache the
            connection.  Use it to fetch feedback from APNs and then close when
            you are done.

            :Arguments:
                - address (str or tuple): target address.
                - certificate (:class:`BaseCertificate`): provider's certificate instance.
                - cert_params (kwargs): :class:`BaseCertificate` arguments, used if ``certificate`` instance is not given.
        """
        if certificate is not None:
            cert = certificate
        else:
            cert = self.pool.get_certificate(cert_params)

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
                - feedback_sandbox -- ``("feedback.sandbox.push.apple.com", 2196)``
                - feedback_production -- ``("feedback.push.apple.com", 2196)``

            :Arguments:
                - address (str or tuple): target address.
                - certificate (:class:`BaseCertificate`): provider's certificate instance.
                - cert_params (kwargs): :class:`BaseCertificate` arguments, used if ``certificate`` instance is not given.
        """
        if certificate is not None:
            cert = certificate
        else:
            cert = self.pool.get_certificate(cert_params)

        address = self.get_address(address)
        return Connection(address, cert, self, use_cache=True)

    def outdate(self, delta):
        """ Close open unused connections in the pool that are left untouched
            for more than ``delta`` time.

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
        # NOTE: global package datetime can become None if session is stored in
        # a global variable and being garbage collected with the rest of the module.
        if datetime is not None:
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
                - certificate (:class:`BaseCertificate`) - provider certificate.
                - session (object) - parent session.
                - use_cache (bool) - True if connections may be cached in the pool.
        """
        self.address = address
        self.certificate = certificate
        self.session = session
        self.use_cache = use_cache
        self._reused = False
        self._connection = None
        self._lock = self.session.pool.create_lock()

    def __enter__(self):
        try:
            if LOG.isEnabledFor(logging.DEBUG):
                LOG.debug("Entering networking session")

            self._lock.acquire() # block until lock is given
            self._open_connection() # can raise exception, bubblit up to the top
        except:
            self._lock.release()
            raise

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            if LOG.isEnabledFor(logging.DEBUG):
                LOG.debug("Leaving networking session%s%s",
                          " with still open connection" if self._connection else "",
                          " because of failure" if exc_type else "",
                          exc_info=(exc_type is not None))

            # the only possible scenario when connection is left open while
            # we are here is when some totally unexpected exception bubbles up.
            assert exc_type is not None or self._connection is None
            if self._connection:
                # terminate connection in case of an error
                self._close(terminate=True)
        finally:
            self._lock.release()

        # we return None, which is False, which forces python to re-raise on error

    def send(self, message):
        """ Send message. """
        # will raise exception if non-cached connection has been used
        with self:
            batch = message.batch(self.session.write_buffer_size)
            failed_after = None
            status = None
            total_sent = 0
            decoder = ResponseDecoder()
            for iteration, (sent, chunk) in enumerate(batch):
                assert len(chunk) > 0
                total_sent += len(chunk)

                if iteration == 0:
                    # can raise exception if new connection is failed to open.
                    # write doesn't return anything, but we are interested in IO failures.
                    _, io_exception = self._ensuring_io(lambda con: con.write(chunk, self.session.write_timeout))
                    if io_exception is not None:
                        # IO failure on first write, sent is 0 here, retry with
                        # the whole message
                        failed_after = sent
                        break
                else:
                    # other writes, that fail naturally
                    try:
                        ret = self._connection.write(chunk, self.session.write_timeout)
                    except:
                        # IO failure on subsequent writes, some of the tokens are
                        # sent, break on the beginning of this batch
                        failed_after = sent
                        break

                # check for possibly arriving failure frame
                try:
                    # should either return sequence of bytes or None if read buffer
                    # is empty.
                    ret = self._connection.peek(256) # status frame is 6 bytes
                except:
                    # Peek failed, which means our read operations fail
                    # abnormaly. I don't like that and the final read will
                    # probably fail too. So fail early, possibly messing the
                    # first batch, but not everything
                    failed_after = sent
                    break
                else:
                    if ret is not None:
                        decoder.feed(ret)
                        # status is not None only if previous iteration got
                        # successful status, but it appears not to be the last
                        # chunk. this should not happen by APNs protocol, still
                        # we have to handle it. the easy solution: ignore
                        # previous status (probably garbage in read buffer)
                        # with a warning.
                        if status is not None:
                            LOG.warning("Got success frame while batch is not comleted. Frame ignored.")

                        # NOTE: it is possible we get None here because not all
                        # bytes could be read without blocking. on next iteration
                        # or final blocking read we will get the rest of the bytes.
                        status = decoder.decode()
                        if status is not None and status[0] != 0: # error detected
                            if LOG.isEnabledFor(logging.INFO):
                                LOG.info("Message send failed midway with status %r to address %r. Sent tokens: %s, bytes: %s",
                                         status, self.address, sent, total_sent)

                            # some shit had happened, response from APNs, bail out and prepare for retry
                            self._close(terminate=True)
                            return status
                    # else: nothing in the read buffer, keep sending

            # by this time we either stopped prematurely on IO error with
            # failed_after set or we finished all batches, possibly having
            # status read with non-blocking IO.

            # the write stream possibly failed, but the read stream might be still
            # open with status frame precisely pointing to failed token.
            if status is None:
                # read status frame, could take 2 iterations if the fist one returns
                # just the read buffer with few bytes not making the whole status frame.
                while True:
                    try:
                        ret = self._connection.read(256, self.session.read_tail_timeout)
                    except:
                        # one of two things had happened:
                        #  - everything went fine, we waited for the final status
                        #    frame the tail timeout of time and got nothing (timeout).
                        #    this is a success condition according to APNs documentation
                        #    if status frame with code 0 is not sent (it is never sent).
                        #  - reading failed with some other exception. we don't know
                        #    starting from which token the batch has failed. we can't
                        #    attempt to read status frame again, because read stream
                        #    is probably closed by now. there is nothing we can do
                        #    except pretending everything is OK. the failed tokens
                        #    will be reported by feedback. the tokens that didn't got
                        #    the message... well, so is life, we can't detect them.
                        #
                        # Sorry, but this is how APNs protocol designed, I can't
                        # do better here. APNs developers suck hard.
                        #
                        # We still have to check failed_after, it tells us when
                        # IO write failed. If failed_after is not None, then
                        # we got here probably because connection is closed for
                        # read and write after the write failure.
                        break
                    else:
                        if ret is not None:
                            decoder.feed(ret)
                            status = decoder.decode()
                            if status is None:
                                # we got bytes, but not enogugh for the status frame.
                                continue

                            # complete status frame read, evaluate
                            if status[0] != 0:
                                if LOG.isEnabledFor(logging.INFO):
                                    LOG.info("Message send failed with status %r to address %r. Sent tokens: %s, bytes: %s",
                                             status, self.address, len(message.tokens), total_sent)

                                # some shit had indeed happened
                                self._close(terminate=True)
                                return status

                        # got a successful status or read ended with closed connection
                        break

            # by this time we have either successful status frame (code 0) or
            # we failed to obtain status frame at all. the failed_after is not None
            # if IO write failed before.

            # there are some bytes read, but we failed to read complete status
            # frame.  all possible timeouts are exceeded or read stream is
            # totally fucked up, so we can't wait and read again. let the user
            # know this happened and treat the situation as if no frame was
            # received at all. APNs protocol sucks sooo much.
            if status is None and decoder._buf:
                LOG.warning("Failed to read complete status frame from %r, but has read some bytes before. Probably read timeout %s is to short.",
                            self.address, self.session.read_tail_timeout)

                # close connection, it is failing
                self._close(terminate=True)

            # normall successs scenario with success frame provided. never
            # happens according to APNs documentation (no status frame gets
            # sent on success), but can happen logically.
            if failed_after is None and status is not None and status[0] == 0:
                # success, release connection for re-use if it was meant for reuse
                self._close(terminate=not self._reused)
                return status

            # everything looks like success, but it might be because read stream
            # was closed or just timeouted. check write IO failure.
            if failed_after is not None:
                if LOG.isEnabledFor(logging.INFO):
                    LOG.info("Message send failed midway with status %r to address %r. Sent tokens: %s, bytes: %s",
                             status, self.address, failed_after, total_sent)

                # close connection, it is failing
                self._close(terminate=True)
                return (255, failed_after + 1)

            # we have sent message to all target tokens and have waited for
            # tail_timeout for any error reponse to arrive. Nothing arrived
            # (hopefully not because read error) and we did not fail with write
            # failure middle on the road, so according to Apple's manual
            # everything went OK. This protocol sucks.
            if LOG.isEnabledFor(logging.DEBUG):
                LOG.debug("Message sent successfully to address %r. Sent tokens: %s, bytes: %s",
                         self.address, len(message.tokens), total_sent)

            # success, release connection for re-use if it was meant for reuse
            self._close(terminate=not self._reused)
            return None

    def feedback(self):
        """ Read and parse feedback information. """
        if self.use_cache:
            # sanity check
            LOG.warning("Don't use cached connections for feedback, you might get stale data.")

        # will raise exception if non-cached connection has been used
        with self:
            # on connection failure we bubble up the exceptions. on IO failure
            # we get the exception as return value, stopping the iteration normally.
            data, io_exception = self._ensuring_io(lambda con: con.read(self.session.read_buffer_size, self.session.read_timeout))
            # data is non empty sequence of bytes on success, None if connection
            # has been closed or on failure. io_exception is not None on IO errors.

            feedback = FeedbackDecoder()
            total_records = 0
            failed = io_exception is not None
            while data is not None:
                feedback.feed(data)
                # TODO: use yield from
                for record in feedback.decoded():
                    total_records += 1
                    yield record

                try:
                    # read next chunk, leaving again either sequence of bytes or
                    # None if connection has been closed.
                    data = self._connection.read(self.session.read_buffer_size, self.session.read_timeout)
                except:
                    # IO failure, probably because of a timeout. break the loop,
                    # we will fetch the rest during the next session.
                    failed = True
                    break

            # there is no point to keep this connection open
            if LOG.isEnabledFor(logging.DEBUG):
                LOG.debug("Feedback received %s records from address %r. Stopped %s",
                         total_records, self.address, "by failure" if failed else "successfully")

            # always close feedback connection, preventing stale data
            self._close(terminate=True)

    def _ensuring_io(self, func):
        """ Re-opens connection if read or write has failed. Used to re-initialize
            connections from the pool with a transport not supporting reliable
            socket closed condition.
        """
        failed = False
        if self._reused:
            # if connection is reused, then there might be left over bytes in the
            # read buffer. flush them.
            try:
                self._connection.reset()
            except:
                LOG.info("Failed to reset connection to %r", self.address, exc_info=True)
                # close the connection, prepare for re-connect
                self._close(terminate=True)
                failed = True

        if not failed:
            # OK, reset succeeded or this is a fresh new connetion
            try:
                return func(self._connection), None
            except Exception as exc:
                if self.session.pool.can_detect_close or not self._reused:
                    # bubble up IO related problem on non-cached connection
                    return None, exc

        # Either failed by reset or failed by IO operation. If
        # pool.can_detect_close is False and we are reusing the connection from
        # the cache pool, then it was probably already failing when we got it.
        # Re-get the connection from the pool again.
        if LOG.isEnabledFor(logging.DEBUG):
            LOG.debug("Re-opening connection to address %r", self.address)

        # ensure failing connection is closed
        self._close(terminate=True)
        # open new connection. this operation might raise exceptions, which
        # will propagate to the outer most caller indicating severe network
        # errors.
        self._open_connection(by_failure=True)
        return self._ensuring_io(func)

    def _open_connection(self, by_failure=False):
        """ Request new connection handle from underlying pool. """
        # use pool if caching is requested or we are ensuring connection with
        # cache enabled.
        if self.use_cache and (not by_failure or self.session.pool.use_cache_for_reconnects):
            if LOG.isEnabledFor(logging.DEBUG):
                LOG.debug("Open cached connection to %r%s.", self.address, " by failure" if by_failure else "")

            self._connection = self.session.pool.get_cached_connection(
                self.address,
                self.certificate,
                timeout=self.session.connect_timeout
            )
            self._reused = True
        else:
            if LOG.isEnabledFor(logging.DEBUG):
                LOG.debug("Open new connection to %r%s.", self.address, " by failure" if by_failure else "")

            self._connection = self.session.pool.get_new_connection(
                self.address,
                self.certificate,
                timeout=self.session.connect_timeout
            )
            self._reused = False

    def _close(self, terminate=False):
        """ Close connection. """
        if self._connection:
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
