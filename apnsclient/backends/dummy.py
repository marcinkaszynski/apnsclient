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

from . import BaseBackend, BaseConnection

# python 3 support
import six

# module level logger
LOG = logging.getLogger(__name__)


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
        return Connection(self, address, certificate)


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
        self.pool.push_result_pos += 1
        return True

    def write(self, data, timeout):
        """ Does nothing, always succeeds. """
        return True

    def read(self, size, timeout):
        """ Reach chunk of data. Returns read bytes or None on any failure or if
            timeout is exceeded. If timeout is zero, then method is not allowed
            to block, but has to return data available in the read buffer or fail
            immediatelly.
        """
        if self.closed():
            return None

        if self.pool.push_results is not None:
            if timeout == 0:
                # only report at the end
                return None

            # we are push connection
            ret = self.pool.push_results[self.pool.push_result_pos % len(self.pool.push_results)]
            if ret is None:
                return six.binary_type()
            
            return pack(">BBI", 8, ret, 0)
        else:
            ret = []
            for x in range(0, self.pool.feedback_results):
                token = six.b("test_{}".format(x))
                ret.append(pack(">IH{}s".format(len(token)), int(time.time()), len(token), token))

            self.close()
            return six.binary_type().join(ret)
