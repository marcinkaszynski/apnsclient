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
import time
from struct import pack

try:
    import threading as _threading
except ImportError:
    import dummy_threading as _threading

from . import BaseBackend, BaseConnection
from ..certificate import BaseCertificate

# python 3 support
import six

# module level logger
LOG = logging.getLogger(__name__)


class Certificate(BaseCertificate):
    """ Dummy certificate """

    def load_context(self, cert_string=None, cert_file=None, key_string=None, key_file=None, passphrase=None):
        """ Returns None as we don't handle any context. """
        return None, None

    def dump_certificate(self, raw_certificate):
        """ Returns dummy contents. All dummy certificates are equal. """
        return "CERTIFICATE"

    def dump_digest(self, raw_certificate, digest):
        """ Returns dummy digsst. All dummy certificates are equal. """
        return self.dump_certificate(raw_certificate)


class Backend(BaseBackend):
    """ Dummy backend designed for testing without performing real IO. Serves
        as an exmple for your custom backends.
    """
    # simulate stdio behavior
    can_detect_close = False

    def __init__(self, push=None, feedback=None, **options):
        """ Create new backend.
        
            :Arguments:
                - push (list): list of status codes to return while sending messages.
                - feedback (int): number of tokens to generate in the feedback stream.
        """
        super(Backend, self).__init__(**options)
        self.push_results = push
        self.push_result_pos = -1
        self.feedback_results = feedback
        self.new_connections = 0
        assert (push is not None) ^ (feedback is not None), "Push results or feedback stream must be provided"

    def get_new_connection(self, address, certificate, timeout=None):
        """ Open a new connection.
        
            :Arguments:
                - address (tuple): target (host, port).
                - certificate (:class:`Certificate`): certificate instance.
                - timeout (float): connection timeout in seconds
        """
        self.new_connections += 1
        self.push_result_pos += 1
        return Connection(self, address, certificate)

    def get_certificate(self, cert_params):
        """ Create/load certificate from parameters. """
        return Certificate(**cert_params)

    def create_lock(self):
        """ Provides semaphore with ``threading.Lock`` interface. """
        return _threading.Lock()


class Connection(BaseConnection):
    """ Dummy connection. """

    def __init__(self, pool, address, certificate):
        """ Create new dummy connection.
        
            :Arguments:
                - pool (:class:`Backend`): dummy backend.
                - address (tuple): target host and port.
                - certificate (:class:`Certificate`): provider certificate.
        """
        super(Connection, self).__init__(address, certificate)
        self.pool = pool
        self._closed = False

    def closed(self):
        """ Returns True if :func:`close` has been explicitly called. """
        return self._closed

    def close(self):
        """ Marks this connection as closed. """
        self._closed = True

    def reset(self):
        """ Reset dummy connection to use next result record. """
        pass

    def write(self, data, timeout):
        """ Does nothing, always succeeds. """
        if self.closed():
            raise IOError("Connection closed")
    
    def peek(self, size):
        """ Always returns None as we never fail prematurely. """
        return None

    def read(self, size, timeout):
        """ Iterates over preconfigured send/feedback responses. """
        if self.closed():
            return None

        if self.pool.push_results is not None:
            # we are push connection
            ret = self.pool.push_results[self.pool.push_result_pos % len(self.pool.push_results)]
            if ret is not None:
                ret = pack(">BBI", 8, ret, 0)

            return ret
        else: # feedback mode
            ret = []
            for x in range(0, self.pool.feedback_results):
                token = six.b("test_{}".format(x))
                ret.append(pack(">IH{}s".format(len(token)), int(time.time()), len(token), token))

            self.close()
            return six.binary_type().join(ret)
