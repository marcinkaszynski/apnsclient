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

import json
import time
import datetime
import logging
from struct import pack

# python 3 support
import six
import binascii


__all__ = ('APNs', 'Message', 'Result')

# module level logger, defaults to "apnsclient.apns"
LOG = logging.getLogger(__name__)


class APNs(object):
    """ APNs multicaster. """

    def __init__(self, connection):
        """ APNs client.

            :Arguments:
                - connection (:class:`Connection`): the connection to talk to.
        """
        self._connection = connection

    def send(self, message):
        """ Send the message.
        
            The method will block until the whole message is sent. The method
            returns :class:`Result` object, which you can examine for possible
            errors and retry attempts.

            .. note::
                If the client fails to connect to APNs, probably because your
                network is down, then this method will raise the related
                exception. However, if connection is successfully established,
                but later on the IO fails, then this method will prepare a
                retry message with the rest of the failed tokens.

            Example::

                # if you use cached connections, then store this session instance
                # somewhere global, such that it will not be garbage collected
                # after message is sent.
                session = Session()
                # get a cached connection, avoiding unnecessary SSL handshake
                con = session.get_connection("push_production", cert_string=db_certificate)
                message = Message(["token 1", "token 2"], alert="Message")
                service = APNs(con)
                try:
                    result = service.send(message)
                except:
                    print "Check your network, I could not connect to APNs"
                else:
                    for token, (reason, explanation) in result.failed.items():
                        delete_token(token) # stop using that token

                    for reason, explanation in result.errors:
                        pass # handle generic errors

                    if result.needs_retry():
                        # extract failed tokens as new message
                        message = message.retry()
                        # re-schedule task with the new message after some delay

            :Returns:
                :class:`Result` object with operation results.
        """
        if len(message.tokens) == 0:
            LOG.warning("Message without device tokens is ignored")
            return Result(message)

        status = self._connection.send(message)
        return Result(message, status)

    def feedback(self):
        """ Fetch feedback from APNs.

            The method returns generator of ``(token, datetime)`` pairs,
            denoting the timestamp when APNs has detected the device token is
            not available anymore, probably because application was
            uninstalled. You have to stop sending notifications to that device
            token unless it has been re-registered since reported timestamp.
            
            Unlike sending the message, you should fetch the feedback using
            non-cached connection. Once whole feedback has been read, this
            method will automatically close the connection.

            .. note::
                If the client fails to connect to APNs, probably because your
                network is down, then this method will raise the related
                exception. However, if connection is successfully established,
                but later on the IO fails, then this method will simply stop
                iterating. The rest of the failed tokens will be delivered
                during the next feedback session.

            Example::

                session = Session()
                # get non-cached connection, free from possible garbage
                con = session.new_connection("feedback_production", cert_string=db_certificate)
                service = APNs(con)
                try:
                    # on any IO failure after successfull connection this generator
                    # will simply stop iterating. you will pick the rest of the tokens
                    # during next feedback session.
                    for token, when in service.feedback():
                        # every time a devices sends you a token, you should store
                        # {token: given_token, last_update: datetime.datetime.now()}
                        last_update = get_last_update_of_token(token)

                        if last_update < when:
                            # the token wasn't updated after the failure has
                            # been reported, so the token is invalid and you should
                            # stop sending messages to it.
                            remove_token(token)
                except:
                    print "Check your network, I could not connect to APNs"

            :Returns:
                generator over ``(binary, datetime)``
        """
        # FIXME: this library is not idiot proof. If you store returned generator
        # somewhere, then yes, the connection will remain locked.
        for token, timestamp in self._connection.feedback():
            yield (token, self._datetime_from_timestamp(timestamp))

    # override if you use custom datetime or weird timezones
    def _datetime_from_timestamp(self, timestamp):
        """ Converts integer timestamp to ``datetime`` object. """
        return datetime.datetime.fromtimestamp(timestamp)


class Message(object):
    """ The notification message. """
    # JSON serialization parameters. Assume UTF-8 by default.
    json_parameters = {
        'separators': (',',':'),
        'ensure_ascii': False,
    }
    # Default expiry (1 day).
    DEFAULT_EXPIRY = datetime.timedelta(days=1)
    # Default message priority
    DEFAULT_PRIORITY = 10

    def __init__(self, tokens, alert=None, badge=None, sound=None, content_available=None,
                 expiry=None, payload=None, priority=DEFAULT_PRIORITY, extra=None,
                 **extra_kwargs):
        """ The push notification to one or more device tokens.

            Read more `about the payload
            <https://developer.apple.com/library/mac/documentation/NetworkingInternet/Conceptual/RemoteNotificationsPG/Chapters/ApplePushService.html#//apple_ref/doc/uid/TP40008194-CH100-SW1>`_.

            .. note::
                In order to stay future compatible this class doesn't transform
                provided arguments in any way. It is your responsibility to
                provide correct values and ensure the payload does not exceed
                the limit of 256 bytes. You can also generate whole payload
                yourself and provide it via ``payload`` argument. The payload
                will be parsed to init default fields like alert and badge.
                However if parsing fails, then these standard fields will
                become unavailable. If raw payload is provided, then other data
                fields like alert or sound are not allowed.

            :Arguments:
                - tokens (str or list): set of device tokens where to the message will be sent.
                - alert (str or dict): the message; read APNs manual for recognized dict keys.
                - badge (int or str): badge number over the application icon or special value such as "increment".
                - sound (str): sound file to play on arrival.
                - content_available (int): set to 1 to indicate new content is available.
                - expiry (int, datetime or timedelta): timestamp when message will expire.
                - payload (dict or str): JSON-compatible dictionary with the
                   complete message payload. If supplied, it is given instead
                   of all the other, more specific parameters.
                - priority (int): priority of the message, defaults to 10
                - extra (dict): extra payload key-value pairs.
                - extra_kwargs (kwargs): extra payload key-value paris, will be merged with ``extra``.
        """
        if payload is not None and ([v for v in (alert, badge, sound, content_available, extra) if v is not None] or extra_kwargs):
            # Raise an error if both `payload` and the more specific parameters are supplied.
            raise ValueError("Payload specified together with alert/badge/sound/content_available/extra.")

        # single token is provided, wrap as list
        if isinstance(tokens, six.string_types) or isinstance(tokens, six.binary_type):
            tokens = [tokens]

        self._tokens = tokens
        self._payload = payload
        self.priority = int(priority)  # has to be integer because will be formatted into a binary
        self.expiry = self._get_expiry_timestamp(expiry)

        if payload is not None and hasattr(payload, "get") and payload.get("aps"):
            # try to reinit fields from the payload
            aps = payload["aps"]
            self.alert = aps.get("alert")
            self.badge = aps.get("badge")
            self.sound = aps.get("sound")
            self.content_available = aps.get("content-available")
            self.extra = dict([(k, v) for (k, v) in six.iteritems(payload) if k != 'aps'])
        elif payload is None:
            # normal message initialization
            self.alert = alert
            self.badge = badge
            self.sound = sound
            self.content_available = content_available
            _extra = {}
            if extra:
                _extra.update(extra)
            if extra_kwargs:
                _extra.update(extra_kwargs)
            self.extra = _extra
            if 'aps' in self.extra:
                raise ValueError("Extra payload data may not contain 'aps' key.")
        # else: payload provided as unrecognized value, don't init fields,
        # they will raise AttributeError on access

    # override if you use funky expiry values
    def _get_expiry_timestamp(self, expiry):
        """ Convert expiry value to a timestamp (integer).
            Provided value can be a date or timedelta.
        """
        if expiry is None:
            # 0 means do not store messages at all. so we have to choose default
            # expiry, which is here 1 day.
            expiry = self.DEFAULT_EXPIRY

        if isinstance(expiry, datetime.timedelta):
            expiry = self._get_current_datetime() + expiry

        if isinstance(expiry, datetime.datetime):
            expiry = time.mktime(expiry.timetuple())

        return int(expiry)

    # override if you use funky timezones
    def _get_current_datetime(self):
        """ Returns current date and time. """
        return datetime.datetime.now()

    def __getstate__(self):
        """ Returns ``dict`` with ``__init__`` arguments.

            If you use ``pickle``, then simply pickle/unpickle the message object.
            If you use something else, like JSON, then::
                
                # obtain state dict from message
                state = message.__getstate__()
                # send/store the state
                # recover state and restore message
                message_copy = Message(**state)

            .. note::
                The message keeps ``expiry`` internally as a timestamp
                (integer).  So, if values of all other arguments are JSON
                serializable, then the returned state must be JSON
                serializable.  If you get ``TypeError`` when you instantiate
                ``Message`` from JSON recovered state, then make sure the keys
                are ``str``, not ``unicode``.

            :Returns:
                `kwargs` for `Message` constructor.
        """
        if self._payload is not None:
            return {
                'tokens': self.tokens,
                'expiry': self.expiry,
                'payload': self._payload,
                'priority': self.priority,
            }

        return dict([(key, getattr(self, key)) for key in ('tokens', 'alert', 'badge',
                    'sound', 'content_available', 'expiry', 'priority', 'extra')])
    
    def __setstate__(self, state):
        """ Overwrite message state with given kwargs. """
        self._tokens = state['tokens']
        self.extra = {}
        self.expiry = state['expiry']
        self.priority = state['priority']

        if 'payload' in state:
            self._payload = state['payload']
            if hasattr(self._payload, "get") and self._payload.get("aps"):
                aps = self._payload["aps"]
                self.alert = aps.get("alert")
                self.badge = aps.get("badge")
                self.sound = aps.get("sound")
                self.content_available = aps.get("content-available")
                self.extra = dict([(k, v) for (k, v) in six.iteritems(self._payload) if k != 'aps'])
        else:
            self._payload = None
            for key, val in six.iteritems(state):
                if key in ('tokens', 'expiry', 'priority'): # already set
                    pass
                elif key in ('alert', 'badge', 'sound', 'content_available'):
                    setattr(self, key, state[key])
                elif key == 'extra':
                    self.extra.update(state[key])
                else:
                    # legacy serialized object
                    self.extra[key] = val

    @property
    def tokens(self):
        """ List target device tokens. """
        return self._tokens

    @property
    def payload(self):
        """ Returns the payload content as a dict or raw ``payload`` argument value. """
        if self._payload is not None:
            return self._payload
        
        # in v.2 protocol no keys are required, but usually you specify
        # alert or content-available.
        aps = {}

        if self.alert is not None:
            aps['alert'] = self.alert

        if self.badge is not None:
            aps['badge'] = self.badge

        if self.sound is not None:
            aps['sound'] = self.sound

        if self.content_available is not None:
            aps['content-available'] = self.content_available

        ret = {
            'aps': aps,
        }
        
        if self.extra:
            ret.update(self.extra)

        return ret

    def get_json_payload(self):
        """ Convert message to JSON payload, acceptable by APNs. Must return byte string. """
        payload = self.payload
        if not isinstance(payload, six.string_types) and not isinstance(payload, six.binary_type):
            payload = json.dumps(payload, **self.json_parameters)

        # in python2 json will output utf-8 encoded str. in python3 json will output
        # a unicode string. So only for python3 in case of unicode string - encode.
        if not isinstance(payload, six.binary_type):
            payload = payload.encode("utf-8")

        return payload

    def batch(self, packet_size):
        """ Returns binary serializer. """
        payload = self.get_json_payload()
        assert isinstance(payload, six.binary_type), "Payload must be bytes/binary"
        return Batch(self._tokens, payload, self.expiry, self.priority, packet_size)

    def retry(self, failed_index, include_failed):
        """ Create new retry message with tokens from failed index. """
        if not include_failed:
            failed_index += 1

        failed = self._tokens[failed_index:]
        if not failed:
            # nothing to retry
            return None

        state = self.__getstate__()
        state['tokens'] = failed
        return Message(**state)


class Batch(object):
    """ Binary stream serializer. """
    # Frame version. Do not change unless you update binary formats too.
    VERSION = 2

    def __init__(self, tokens, payload, expiry, priority, packet_size):
        """ New serializer.

            :Arguments:
                - tokens (list): list of target target device tokens.
                - payload (str): JSON payload.
                - expiry (int): expiry timestamp.
                - priority (int): message priority.
                - packet_size (int): minimum chunk size in bytes.
        """
        self.tokens = tokens
        self.payload = payload
        self.expiry = expiry
        self.priority = priority
        self.packet_size = packet_size
        
    def __iter__(self):
        """ Iterate over serialized chunks. """
        messages = []
        buf = 0
        sent = 0

        # for all registration ids
        for idx, token in enumerate(self.tokens):
            tok = binascii.unhexlify(token)
            # |COMMAND|FRAME-LEN|{token}|{payload}|{id:4}|{expiry:4}|{priority:1}
            frame_len = 3*5 + len(tok) + len(self.payload) + 4 + 4 + 1 # 5 items, each 3 bytes prefix, then each item length
            fmt = ">BIBH{0}sBH{1}sBHIBHIBHB".format(len(tok), len(self.payload))
            message = pack(fmt, self.VERSION, frame_len,
                    1, len(tok), tok,
                    2, len(self.payload), self.payload,
                    3, 4, idx,
                    4, 4, self.expiry,
                    5, 1, self.priority)

            messages.append(message)
            buf += len(message)
            if buf >= self.packet_size:
                chunk = six.b("").join(messages)
                buf = 0
                prev_sent = sent
                sent += len(messages)
                messages = []
                yield prev_sent, chunk

        # last small chunk
        if messages:
            yield sent, six.b("").join(messages)


class Result(object):
    """ Result of send operation. """
    # all rerror codes {code: (explanation, can retry?, include failed token?)}
    ERROR_CODES = {
        1: ('Processing error', True, True),
        2: ('Missing device token', True, False), # looks like token was empty?
        3: ('Missing topic', False, True), # topic is encoded in the certificate, looks like certificate is wrong. bail out.
        4: ('Missing payload', False, True), # bail out, our message looks like empty
        5: ('Invalid token size', True, False), # current token has wrong size, skip it and retry
        6: ('Invalid topic size', False, True), # can not happen, we do not send topic, it is part of certificate. bail out.
        7: ('Invalid payload size', False, True), # our payload is probably too big. bail out.
        8: ('Invalid token', True, False), # our device token is broken, skipt it and retry
        10: ('Shutdown', True, False), # server went into maintenance mode. reported token is the last success, skip it and retry.
        None: ('Unknown', True, True), # unknown error, for sure we try again, but user should limit number of retries
    }

    def __init__(self, message, failure=None):
        """ Result of send operation. """
        self.message = message
        self._retry_message = None
        self._failed = {}
        self._errors = []

        if failure is not None:
            reason, failed_index = failure
            if reason not in self.ERROR_CODES:
                # one of "unknown" error codes
                reason = None

            expl, can_retry, include_failed = self.ERROR_CODES[reason]
            if can_retry:
                # may be None if failed on last token, which is skipped
                self._retry_message = message.retry(failed_index, include_failed)

            if reason == 10:
                # the Shutdown reason is not really an error, it just indicates
                # the server went into a maintenance mode and connection was closed.
                # The reported token is the last one successfully sent.
                pass
            elif not include_failed: # report broken token, it was skipped
                self._failed = {
                    message.tokens[failed_index]: (reason, expl)
                }
            else: # errors not related to broken token, global shit happened
                self._errors = [
                    (reason, expl)
                ]

            if LOG.isEnabledFor(logging.DEBUG):
                LOG.debug("Batch of %d tokens failed: %s.%s%s",
                          len(message.tokens), expl,
                          ' With errors.' if self._errors else '',
                          ' With failed tokens.' if self._failed else '')

    @property
    def errors(self):
        """ Returns list of ``(reason, explanation)`` pairs denoting severe errors,
            not related to failed tokens. The reason is an integer code as
            described in APNs tutorial.

            The following codes are considered to be errors:
                - ``(1, "Processing error")``
                - ``(3, "Missing topic")``
                - ``(4, "Missing payload")``
                - ``(6, "Invalid topic size")``
                - ``(7, "Invalid payload size")``
                - ``(None, "Unknown")``, usually some kind of IO failure.
        """
        return self._errors

    @property
    def failed(self):
        """ Reports failed tokens as ``{token : (reason, explanation)}`` mapping.

            Current APNs protocols bails out on first failed device token, so
            the returned dict will contain at most 1 entry. Future extensions
            may upgrade to multiple failures in a batch. The reason is the
            integer code as described in APNs tutorial.

            The following codes are considered to be token failures:
                - ``(2, "Missing device token")``
                - ``(5, "Invalid token size")``
                - ``(8, "Invalid token")``
        """
        return self._failed

    def needs_retry(self):
        """
            Returns True if there are tokens that should be retried.

            .. note::
                In most cases if ``needs_retry`` is true, then the reason of
                incomplete batch is to be found in ``errors`` and ``failed``
                properties. However, Apple added recently a special code *10
                - Shutdown*, which indicates server went into a maintenance
                mode before the batch completed. This response is not really an
                error, so the before mentioned properties will be empty, while
                ``needs_retry`` will be true.
        """
        return self._retry_message is not None

    def retry(self):
        """ Returns :class:`Message` with device tokens that can be retried.
       
            Current APNs protocol bails out on first failure, so any device
            token after the failure should be retried. If failure was related
            to the token, then it will appear in :attr:`failed` set and will be
            in most cases skipped by the retry message.
        """
        return self._retry_message
