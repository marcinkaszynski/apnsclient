if __name__ == '__main__':
    import os.path, sys
    sys.path.append(os.path.dirname(os.path.dirname(__file__)))

import unittest, struct, pickle, json
import time
import datetime
from mock import patch
from OpenSSL.SSL import ZeroReturnError

# python 3 support
import six
import binascii

from apnsclient import *



class APNsTest(unittest.TestCase):
    """ Test APNs client. """

    @patch('OpenSSL.SSL')
    @patch('OpenSSL.crypto')
    def setUp(self, mycrypto, myssl):
        myssl.crypto.dump_certificate.return_value = 'certificate'

        self.session = Session()
        self.push_con = self.session.get_connection("push_production", cert_string='certificate_content')
        self.same_push_con = self.session.get_connection("push_production", cert_string='certificate content')

        self.feed_con = Session.new_connection("feedback_production", cert_string='certificate_content')
        self.same_feed_con = Session.new_connection("feedback_production", cert_string='certificate_content')

    @patch('OpenSSL.SSL')
    def test_session(self, myssl):
        self.assertEqual(self.push_con, self.same_push_con)
        self.assertNotEqual(self.feed_con, self.same_feed_con)
        
        self.assertTrue(self.push_con.is_closed())
        self.push_con.refresh()
        self.assertFalse(self.push_con.is_closed())

        # can not outdate if few moments
        self.assertEqual(self.session.outdate(datetime.timedelta(minutes=5)), 0)
        self.assertFalse(self.push_con.is_closed())

        self.session.shutdown()
        self.assertTrue(self.push_con.is_closed())

    @patch('OpenSSL.SSL')
    def test_send(self, myssl):
        # fail on invalid token on second message
        myssl.Connection().recv.return_value = struct.pack(">BBI", 8, 8, 1)

        msg = Message(["0123456789ABCDEF", "FEDCBA9876543210"], alert="my alert", badge=10, content_available=1, my_extra=15)
        self.push_con.close()
        srv = APNs(self.push_con)
        res = srv.send(msg)

        self.assertEqual(len(res.failed), 1)
        self.assertEqual(next(iter(res.failed.keys())), "FEDCBA9876543210")
        # it was the last token and we skip it
        self.assertFalse(res.needs_retry())
        self.assertTrue(self.push_con.is_closed())

    @patch('OpenSSL.SSL')
    def test_feedback(self, myssl):
        myssl.ZeroReturnError = ZeroReturnError

        # fail on invalid token on second message
        token = binascii.unhexlify("0123456789ABCDEF")
        curtime = int(time.time())
        myssl.Connection().recv.side_effect = [struct.pack(">IH%ss" % len(token), curtime, len(token), token), ZeroReturnError()]

        self.feed_con.close()
        srv = APNs(self.feed_con)
        feed = list(srv.feedback())
        self.assertEqual(len(feed), 1)
        self.assertEqual(feed[0], (six.b('0123456789ABCDEF'), datetime.datetime.fromtimestamp(curtime)))


class APNsClientMessageTest(unittest.TestCase):
    """ Test Message API. """

    def setUp(self):
        self.uni = Message("0123456789ABCDEF", alert="alert", badge=10, content_available=1)
        self.multi = Message(["0123456789ABCDEF", "FEDCBA9876543210"], alert="my alerrt", sound="cool.mp3", content_available=1, my_extra=15)
        self.payload = Message(["0123456789ABCDEF", "FEDCBA9876543210"], payload=self.uni.payload, priority=5)

    def test_serialization(self):
        # standard pickle
        suni = pickle.dumps(self.uni)
        smulti = pickle.dumps(self.multi)
        spayload = pickle.dumps(self.payload)
        
        cuni = pickle.loads(suni)
        cmulti = pickle.loads(smulti)
        cpayload = pickle.loads(spayload)

        for key in ('tokens', 'alert', 'badge', 'sound', 'content_available', 'expiry', 'extra', 'priority', '_payload'):
            self.assertEqual(getattr(self.uni, key), getattr(cuni, key))
            self.assertEqual(getattr(self.multi, key), getattr(cmulti, key))
            self.assertEqual(getattr(self.payload, key), getattr(cpayload, key))

        # custom
        suni = self.uni.__getstate__()
        smulti = self.multi.__getstate__()
        spayload = self.payload.__getstate__()
        # JSON/XML/etc and store/send
        suni = json.dumps(suni)
        smulti = json.dumps(smulti)
        spayload = json.dumps(spayload)

        suni = json.loads(suni)
        smulti = json.loads(smulti)
        spayload = json.loads(spayload)

        if six.PY2:
            suni = dict((k.encode("UTF-8"), v) for k, v in six.iteritems(suni))
            smulti = dict((k.encode("UTF-8"), v) for k, v in six.iteritems(smulti))
            spayload = dict((k.encode("UTF-8"), v) for k, v in six.iteritems(spayload))

        cuni = Message(**suni)
        cmulti = Message(**smulti)
        cpayload = Message(**spayload)

        for key in ('tokens', 'alert', 'badge', 'sound', 'content_available', 'expiry', 'extra', 'priority', '_payload'):
            self.assertEqual(getattr(self.uni, key), getattr(cuni, key))
            self.assertEqual(getattr(self.multi, key), getattr(cmulti, key))
            self.assertEqual(getattr(self.payload, key), getattr(cpayload, key))

    def test_batch(self):
        # binary serialization in ridiculously small buffer =)
        buni = list(self.uni.batch(10))
        bmulti = list(self.multi.batch(10))

        # number of batches
        self.assertEqual(len(buni), 1)
        self.assertEqual(len(bmulti), 2)

        # lets read stuff back. number of sent before ID's is of course 0.
        self.check_message(buni[0], 0, self.uni)
        self.check_message(bmulti[0], 0, self.multi)
        self.check_message(bmulti[1], 1, self.multi)

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
        runi = self.uni.retry(0, True)
        for key in ('tokens', 'alert', 'badge', 'sound', 'content_available', 'expiry', 'priority', 'extra'):
            self.assertEqual(getattr(self.uni, key), getattr(runi, key))

        # nothing to retry, we skip the token
        self.assertEqual(self.uni.retry(0, False), None)

        # include failed
        rmulti = self.multi.retry(0, True)
        for key in ('tokens', 'alert', 'badge', 'sound', 'content_available', 'expiry', 'priority', 'extra'):
            self.assertEqual(getattr(self.multi, key), getattr(rmulti, key))

        # skip failed
        rmulti = self.multi.retry(0, False)
        self.assertEqual(self.multi.tokens[1:], rmulti.tokens)
        for key in ('alert', 'badge', 'sound', 'content_available', 'expiry', 'priority', 'extra'):
            self.assertEqual(getattr(self.multi, key), getattr(rmulti, key))

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


class APNsClientResultTest(unittest.TestCase):
    """ Test Result API. """

    def setUp(self):
        self.msg = Message(["0123456789ABCDEF", "FEDCBA9876543210"], alert="my alerrt", sound="cool.mp3", my_extra=15)

    def test_result(self):
        for reason in Result.ERROR_CODES.keys():
            res = Result(self.msg, (reason, 0))
            self.assertEqual(len(res.errors), int(reason in (1, 3, 4, 6, 7, 10, None)))
            self.assertEqual(len(res.failed), int(reason in (2, 5, 8)))
            self.assertEqual(reason in (1, 2, 5, 8, 10, None), res.needs_retry())

            if res.needs_retry():
                ret = res.retry()
                # skip failed or successful token by Shutdown
                self.assertEqual(len(ret.tokens), 2 - len(res.failed) - int(reason == 10))


if __name__ == '__main__':
    unittest.main()
