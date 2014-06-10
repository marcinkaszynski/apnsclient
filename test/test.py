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

if __name__ == '__main__':
    import os.path, sys
    sys.path.append(os.path.dirname(os.path.dirname(__file__)))

import unittest, struct, pickle, json, datetime

# python 3 support
import six
import binascii

from apnsclient import Message, Session, APNs
from apnsclient.apns import Result
from apnsclient.backends.dummy import Backend as DummyBackend



class APNsClientMessageTest(unittest.TestCase):
    """ Test Message API. """

    def setUp(self):
        self.now = datetime.datetime.now()
        # Typical message
        self.message = Message(
            "0123456789ABCDEF",
            alert=u"Russian: \u0421\u0430\u0440\u0434\u0430\u0440",
            badge=10,
            sound="test.mp3",
            content_available=1,
            expiry=self.now + datetime.timedelta(days=3),
            priority=30,
            extra={'key': 'value'}
        )
        # Message with a custom payload
        self.raw_message = Message(
            ["0123456789ABCDEF", "FEDCBA9876543210"],
            payload=self.message.payload,
            priority=5,
            expiry=datetime.timedelta(days=5)
        )

    def test_payload(self):
        payload = self.message.get_json_payload()
        self.assertIsInstance(payload, six.binary_type)
        unicode_src = payload.decode('utf-8')
        payload = json.loads(unicode_src)
        self.assertEqual(payload["aps"], {
            "alert": self.message.alert,
            "badge": self.message.badge,
            "sound": self.message.sound,
            "content-available": self.message.content_available
        })
        for k, v in self.message.extra.items():
            self.assertEqual(payload[k], v)

    def test_serialization(self):
        # standard pickle
        s_message = pickle.dumps(self.message)
        s_raw_message = pickle.dumps(self.raw_message)
        c_message = pickle.loads(s_message)
        c_raw_message = pickle.loads(s_raw_message)

        for key in ('tokens', 'alert', 'badge', 'sound', 'content_available', 'expiry', 'extra', 'priority', '_payload'):
            self.assertEqual(getattr(self.message, key), getattr(c_message, key))
            self.assertEqual(getattr(self.raw_message, key), getattr(c_raw_message, key))

        # custom
        s_message = self.message.__getstate__()
        s_raw_message = self.raw_message.__getstate__()
        # JSON/XML/etc and store/send
        s_message = json.dumps(s_message)
        s_raw_message = json.dumps(s_raw_message)
        # unserialize
        s_message = json.loads(s_message)
        s_raw_message = json.loads(s_raw_message)
        # reconstruct
        c_message = Message(**s_message)
        c_raw_message = Message(**s_raw_message)

        for key in ('tokens', 'alert', 'badge', 'sound', 'content_available', 'expiry', 'extra', 'priority', '_payload'):
            self.assertEqual(getattr(self.message, key), getattr(c_message, key))
            self.assertEqual(getattr(self.raw_message, key), getattr(c_raw_message, key))

    def test_non_ascii(self):
        # meta-data size. ensure 'alert' is included.
        empty_msg_size = len(Message(tokens=[], alert="a").get_json_payload()) - 1

        MAX_UTF8_SIZE = 3  # size of maximum utf8 encoded character in bytes
        chinese_str = (
            u'\u5187\u869a\u5487\u6b8f\u5cca\u9f46\u9248\u6935\u4ef1\u752a'
            u'\u67cc\u521e\u62b0\u530a\u6748\u9692\u5c6e\u653d\u588f\u6678')
        chinese_msg_size = len(Message(tokens=[], alert=chinese_str).get_json_payload())
        self.assertLessEqual(
            chinese_msg_size,
            empty_msg_size + len(chinese_str) * MAX_UTF8_SIZE)

        MAX_EMOJI_SIZE = 4  # size of maximum utf8 encoded character in bytes
        # emoji
        emoji_str = (u'\U0001f601\U0001f603\U0001f638\U00002744')
        emoji_msg_size = len(Message(tokens="", alert=emoji_str).get_json_payload())
        self.assertLessEqual(
            emoji_msg_size,
            empty_msg_size + len(emoji_str) * MAX_EMOJI_SIZE)

    def test_batch(self):
        # binary serialization in ridiculously small buffer =)
        b_message = list(self.message.batch(10))
        b_raw_message = list(self.raw_message.batch(10))

        # number of batches
        self.assertEqual(len(b_message), 1)
        self.assertEqual(len(b_raw_message), 2)

        # lets read stuff back. number of sent before ID's is of course 0.
        self.check_message(b_message[0], 0, self.message)
        self.check_message(b_raw_message[0], 0, self.raw_message)
        self.check_message(b_raw_message[1], 1, self.raw_message)

    def check_message(self, batch, itr, msg):
        sent, data = batch
        # we send batches of 1 token size
        self.assertEqual(sent, itr)
        # |COMMAND|FRAME-LEN|{token}|{payload}|{id:4}|{expiry:4}|{priority:1}
        command, frame_len = struct.unpack(">BI", data[0:5])
        self.assertEqual(command, 2)
        self.assertEqual(frame_len, len(data) - 5)
        
        off = 5
        restored = {}
        for itm in range(1, 6):
            hdr, length = struct.unpack(">BH", data[off:(off+3)])
            off += 3
            value = data[off:(off+length)]
            off += length
            if hdr == 1:
                restored['token'] = binascii.hexlify(value).decode('ascii')
            elif hdr == 2:
                restored['payload'] = json.loads(value.decode('utf-8'))
            elif hdr == 3:
                restored['index'] = struct.unpack(">I", value)[0]
            elif hdr == 4:
                restored['expiry'] = struct.unpack(">I", value)[0]
            elif hdr == 5:
                restored['priority'] = struct.unpack(">B", value)[0]

        for key in ('token', 'payload', 'index', 'expiry', 'priority'):
            if key not in restored:
                self.fail("Binary message is missing: %s" % key)

        # check message
        self.assertEqual(msg.tokens[itr].lower(), restored['token'].lower())
        self.assertEqual(msg.payload['aps'], restored['payload']['aps'])
        restored['payload'].pop('aps')
        self.assertEqual(msg.extra, restored['payload'])
        self.assertEqual(restored['index'], itr)
        self.assertEqual(msg.expiry, restored['expiry'])
        self.assertEqual(msg.priority, restored['priority'])

    def test_retry(self):
        # include failed
        r_message = self.message.retry(0, True)
        for key in ('tokens', 'alert', 'badge', 'sound', 'content_available', 'expiry', 'priority', 'extra'):
            self.assertEqual(getattr(self.message, key), getattr(r_message, key))

        # nothing to retry, we skip the token
        self.assertEqual(self.message.retry(0, False), None)

        # include failed
        r_raw_message = self.raw_message.retry(0, True)
        for key in ('tokens', 'alert', 'badge', 'sound', 'content_available', 'expiry', 'priority', 'extra'):
            self.assertEqual(getattr(self.raw_message, key), getattr(r_raw_message, key))

        # skip failed
        r_raw_message = self.raw_message.retry(0, False)
        self.assertEqual(self.raw_message.tokens[1:], r_raw_message.tokens)
        for key in ('alert', 'badge', 'sound', 'content_available', 'expiry', 'priority', 'extra'):
            self.assertEqual(getattr(self.raw_message, key), getattr(r_raw_message, key))


class APNsClientResultTest(unittest.TestCase):
    """ Test Result API. """

    def setUp(self):
        self.msg = Message(["0123456789ABCDEF", "FEDCBA9876543210"], alert="message")

    def test_result(self):
        for reason in Result.ERROR_CODES.keys():
            res = Result(self.msg, (reason, 0))
            self.assertEqual(len(res.errors), int(reason in (1, 3, 4, 6, 7, None)))
            self.assertEqual(len(res.failed), int(reason in (2, 5, 8)))
            self.assertEqual(reason in (1, 2, 5, 8, 10, None), res.needs_retry())

            if res.needs_retry():
                ret = res.retry()
                # skip failed or successful token by Shutdown
                self.assertEqual(len(ret.tokens), 2 - len(res.failed) - int(reason == 10))


class APNsDummyTest(unittest.TestCase):
    """ Test APNs client with dummy backend. """

    def test_send(self):
        # success, retry + include-failed, don't-retry + include-failed
        backend = DummyBackend(push=(None, 1, 3))
        session = Session(pool=backend)

        msg = Message(["0123456789ABCDEF", "FEDCBA9876543210"], alert="my alert", badge=10, content_available=1, my_extra=15)
        push_con = session.get_connection("push_production", cert_string="certificate")
        srv = APNs(push_con)
        res = srv.send(msg)
        self.assertEqual(len(res.failed), 0)
        self.assertEqual(len(res.errors), 0)
        self.assertFalse(res.needs_retry())

        push_con2 = session.get_connection("push_production", cert_string="certificate")
        srv = APNs(push_con2)
        self.assertEqual(session.pool.push_result_pos, 0)
        session.pool.push_result_pos += 1
        res = srv.send(msg)
        self.assertEqual(len(res.failed), 0)
        self.assertEqual(len(res.errors), 1)
        self.assertTrue(res.needs_retry())

        # indeed, we have used the cache
        self.assertEqual(session.pool.new_connections, 1)

        push_con = session.new_connection("push_production", cert_string="certificate")
        srv = APNs(push_con)
        res = srv.send(msg)
        self.assertEqual(len(res.failed), 0)
        self.assertEqual(len(res.errors), 1)
        self.assertFalse(res.needs_retry())

        # indeed, new connection, we haven't used the cache
        self.assertEqual(session.pool.new_connections, 2)

    def test_feedback(self):
        backend = DummyBackend(feedback=5)
        session = Session(pool=backend)
        feed_con = session.new_connection("feedback_production", cert_string="certificate")
        srv = APNs(feed_con)
        self.assertEqual(len(list(srv.feedback())), 5)


if __name__ == '__main__':
    unittest.main()
