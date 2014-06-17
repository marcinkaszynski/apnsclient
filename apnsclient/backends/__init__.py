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
#
import datetime

# python 3 support
import six


class BaseBackend(object):
    """ Interface definition for IO backends. """
    #: Default pool size.
    DEFAULT_POOL_SIZE = 5
    #: True if this backend can detect whether the connection is closed when
    # serving ``get_cached_connection()`` call. If False, then APNs will re-get
    # the connection if first IO operation fails. For example, POSIX sockets
    # can't detect if connection is closed until first read or write operation.
    can_detect_close = False

    def __init__(self, pool_size=DEFAULT_POOL_SIZE, use_cache_for_reconnects=True):
        """ Create new backend. The backend will keep a pool of connections for
            each ``(address, certificate)`` pair.

            Every new connetion will be eventually released. If it is not
            closed and the pool size is smaller than ``pool_size``, then
            connection will be added back to the pool. If ``pool_size`` is set
            to None, then pool will grow unlimited. If ``pool_size`` is 0, then
            pool will be effectivly disabled. The connection will be dropped
            from the pool if it gets closed.

            If ``can_detect_close`` is False, then session will try to
            reconnect if first IO operation fails on current connection, which
            is obtained from the cached pool. The argument
            ``use_cache_for_reconnects`` specifies how to obtain new connection
            when reconnecting. If set True, then new connection will be taken
            from the cached pool, otherwise the backend will always open a new
            connection.

            :Arguments:
                - pool_size (int): optimal pool size, None for unlimited size.
                - use_cache_for_reconnects (bool): True to use cache for re-connects.
        """
        self.pool_size = pool_size
        self.use_cache_for_reconnects = use_cache_for_reconnects
        self._connections = {} # (address, certificate) -> [connection]
        self._lock = self.create_lock()

    def get_certificate(self, cert_params):
        """ Create/load certificate from parameters. """
        raise NotImplementedError

    def create_lock(self):
        """ Provides semaphore with ``threading.Lock`` interface. """
        raise NotImplementedError

    def get_cached_connection(self, address, certificate, timeout=None):
        """ Obtain connection from the pool. Opens new connection if no free
            connection is found.

            :Arguments:
                - address (tuple): target (host, port).
                - certificate (:class:`Certificate`): certificate instance.
                - timeout (float): connection timeout in seconds
        """
        key = (address, certificate)
        try:
            self._lock.acquire()
            pool = self._connections.get(key)
            while pool:
                con = pool.pop(0)
                if not con.closed():
                    con.touch()
                    return con
        finally:
            self._lock.release()

        return self.get_new_connection(address, certificate, timeout=timeout)

    def release(self, connection):
        """ Release connection. Method stores connection in the pool if pool
            does not exceed the optimal size.

            :Arguments:
                - connection (object): connection, obtained from this backend.
        """
        if not connection.closed():
            if self.pool_size is None or self.pool_size > 0:
                try:
                    self._lock.acquire()
                    key = (connection.address, connection.certificate)
                    pool = self._connections.setdefault(key, [])
                    if self.pool_size is None or len(pool) < self.pool_size:
                        connection.touch()
                        pool.append(connection)
                        return
                finally:
                    self._lock.release()

            # pool is larger than the optimal size, close surplus connection
            connection.close()

    def get_new_connection(self, address, certificate, timeout=None):
        """ Open a new connection.
        
            :Arguments:
                - address (tuple): target (host, port).
                - certificate (:class:`Certificate`): certificate instance.
                - timeout (float): connection timeout in seconds
        """
        raise NotImplementedError

    def outdate(self, delta):
        """ Close open connections in the pool that are not used in more than
            ``delta`` time.

            You may call this method in a separate thread or run it in some
            periodic task. If you don't, then all connections will remain open
            until session is shut down. It might be an issue if you care about
            your open server connections.

            .. note::
                This method doesn't touch connetions currently being in use,
                even if you specify zero delta. It affects only unused
                connections in the pool.

            :Arguments:
                delta (datetime.timedelta): maximum age of unused connection.
        """
        try:
            self._lock.acquire()
            for key, pool in list(six.iteritems(self._connections)):
                new_pool = []
                for con in pool:
                    if not con.closed():
                        if not con.is_outdated(delta):
                            new_pool.append(con)
                        else:
                            con.close()

                if new_pool:
                    self._connections[key] = new_pool
                else:
                    del self._connections[key]
        finally:
            self._lock.release()

    def __del__(self):
        """ Close conections on destruction. """
        # NOTE: global package datetime can become None if session is stored in
        # a global variable and being garbage collected with the rest of the module.
        if datetime is not None:
            self.outdate(datetime.timedelta())


class BaseConnection(object):
    """ Connection interface. """

    def __init__(self, address, certificate):
        """ Open new connection to given address using given certificate. """
        self.address = address
        self.certificate = certificate
        self.touch()

    def touch(self):
        """ Reset last use timestamp. """
        self.last_use = datetime.datetime.now()

    def is_outdated(self, delta):
        """ Returns True if ``delta`` time has not been passed since the last use.
        
            :Arguments:
                - delta (datetime.timedelta): last use TTL.
        """
        return (datetime.datetime.now() - self.last_use) > delta

    def closed(self):
        """ Returns True if connection is closed via explicit :func:`close' call.
            If ``backend.can_detect_close`` is False, then this method is allowed
            to return False even if underlying connection has been closed by itself.

            .. warning::
                This method is not allowed to throw any exceptions, except
                those that indicate catastrophic events (such as
                out-of-memory). On any IO related failure this method should
                always return True.

            :Returns:
                True if connection is closed or check has been failed, otherwise
                returns False.
        """
        raise NotImplementedError

    def close(self):
        """ Close connection and free underlying resources. Does nothing if
            connection is already closed.
            
            .. warning::
                This method is not allowed to throw any exceptions, except
                those that indicate catastrophic events (such as
                out-of-memory). On any IO related failure this method should
                simply supress the problem and set :func:`closed` state True.
        """
        raise NotImplementedError

    def reset(self):
        """ Clear read and write buffers. Called before starting a new IO
            session using a cached connection. Prevents stale date from being
            read during a new session.
        """
        raise NotImplementedError

    def write(self, data, timeout):
        """ Write chunk of data. Either writes the whole sequence or fails with
            an IO related exception. The exception should be raised if
            connection is closed or not the whole data can be sent within given
            timeout or any other IO error occurs.

            :Arguments:
                - data (bytes): data to write.
                - timeout (float): IO timeout for write operation, None for unlimited blocking.
        """
        raise NotImplementedError

    def peek(self, size):
        """ Read chunk of data from the read buffer without blocking. Returns
            not empty sequence of bytes or None if read buffer is empty. This
            method is used to quickly look for a status frame while sending the
            message block by block. If connection is closed, then method should
            return None.

            :Arguments:
                - size (int): max number of bytes to read.

            :Returns:
                Not empty sequence of bytes or None if read buffer is empty or
                connection is closed.
        """
        raise NotImplementedError

    def read(self, size, timeout):
        """ Read chunk of data. Returns not empty sequence of bytes while
            blocking for at most timeout of seconds. Returns None if connection
            is closed. Raises exception if not a single byte can be read within
            given timeout or on any IO related failure.

            :Arguments:
                - size (int): max number of bytes to read.
                - timeout (float): IO timeout for read operation, None if unlimited.

            :Returns:
                Not empty sequence of bytes or None if connection has been closed.
        """
        raise NotImplementedError

    def __del__(self):
        """ Close conection on destruction. """
        self.close()
