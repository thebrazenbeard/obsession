import unittest
from obsession_lab.opportunity_bridge import DeclaredChannel,candidate_routes,_loopback_port,fetch_tattler_current

class OpportunityTests(unittest.TestCase):
    def setUp(self):
        self.records=[
            {"kind":"tcp_listener","direction":"listen","local":"127.0.0.1:8765","process":{"name":"service"}},
            {"kind":"tcp_session","direction":"outbound","local":"127.0.0.1:1111","remote":"127.0.0.1:8765"},
            {"kind":"tcp_listener","direction":"listen","local":"0.0.0.0:9000"},
        ]

    def test_declared_known_loopback_observation(self):
        x=candidate_routes(self.records,[DeclaredChannel("permitted-demo",8765,True)])
        self.assertEqual(1,len(x["candidates"]))
        self.assertEqual("LOCAL_LISTENER_OBSERVED_ONLY",x["candidates"][0]["status"])
        self.assertFalse(x["candidates"][0]["channel_authenticated"])
        self.assertFalse(x["candidates"][0]["recipient_verified"])
        self.assertFalse(x["message_delivered"])

    def test_foreign_or_arbitrary_listener_no_promotion(self):
        x=candidate_routes(self.records,[DeclaredChannel("foreign",9000)])
        self.assertEqual([],x["candidates"])

    def test_tcp_session_does_not_make_channel(self):
        x=candidate_routes(self.records,[DeclaredChannel("random",1111)])
        self.assertEqual([],x["candidates"])

    def test_loopback_ipv6(self):
        self.assertEqual(9147,_loopback_port("[::1]:9147"))
        self.assertIsNone(_loopback_port("[2001:db8::1]:9147"))

    def test_non_numeric_and_invalid_port(self):
        for x in ("127.0.0.1:0","127.0.0.1:nan","127.0.0.1:77777","malformed"):
            self.assertIsNone(_loopback_port(x))

    def test_outbound_flag_does_not_grant_execution(self):
        x=candidate_routes(self.records,[DeclaredChannel("x",8765,True)])
        self.assertTrue(x["candidates"][0]["outbound_permission_declared"])
        self.assertFalse(x["candidates"][0]["outbound_permission_verified"])
        self.assertEqual(0,x["execution_count"])

    def test_no_forged_tattler_result(self):
        with self.assertRaises(ValueError):
            candidate_routes([{}]*5001,[])

    def test_invalid_channel(self):
        with self.assertRaises(ValueError): DeclaredChannel("not valid!",8765)

    def test_observation_does_not_send(self):
        x=candidate_routes(self.records,[DeclaredChannel("x",8765)])
        self.assertFalse(x["message_delivered"])
        self.assertFalse(x["candidates"][0]["send_attempted"])


if __name__=="__main__":
    unittest.main()