import unittest
from host_verify_serial import evaluate,generate_one_time_challenge,release_approved_from_serial

class TestR105ReadOnlySerialProtocol(unittest.TestCase):
    def setUp(self):
        self.challenge="OPX-R105-CHAL/1/"+"A"*64
        self.good="OPX-R105-READONLY/1/"+"A"*64+"/26100/SYSTEM"

    def test_nonce_is_unique_one_time_and_format_bounded(self):
        a=generate_one_time_challenge()
        b=generate_one_time_challenge()
        self.assertNotEqual(a,b)
        self.assertTrue(a.startswith("OPX-R105-CHAL/1/"))
        self.assertEqual(len(a),len(self.challenge))

    def test_only_expected_system_echo_is_accepted(self):
        ok,reason=evaluate(self.challenge,self.good)
        self.assertTrue(ok)
        self.assertIn("CORROBORATION_ONLY",reason)
        self.assertFalse(release_approved_from_serial(self.challenge,self.good))

    def test_wrong_nonce_or_replay_refused(self):
        for value in [
            self.good.replace("A"*64,"B"*64),
            self.good.lower(), self.good+"\n", self.good+"\r",
            self.good.replace("/26100/","/26101/",1).replace("SYSTEM","NOT_SYSTEM")
        ]:
            if "/26101/NOT_SYSTEM" in value:
                self.assertFalse(evaluate(self.challenge,value)[0])
            elif value.lower()==self.good.lower() and value!=self.good:
                self.assertFalse(evaluate(self.challenge,value)[0])
            else:
                self.assertFalse(evaluate(self.challenge,value)[0])

    def test_wrong_privilege_build_protocol_and_shell_syntax(self):
        for value in [
            self.good.replace("SYSTEM","NOT_SYSTEM"),
            self.good.replace("26100","18999"),
            self.good.replace("26100","9999999"),
            self.good+"; del /f /q C:\\\\",
            self.good+"/CONNECT",
            self.good+" "+("X"*500),
            "", "OPX-R105-READONLY/2/"+"A"*64+"/26100/SYSTEM",
        ]:
            self.assertFalse(evaluate(self.challenge,value)[0])

    def test_non_string_and_bad_host_challenge(self):
        self.assertFalse(evaluate(None,self.good)[0])
        self.assertFalse(evaluate(self.challenge,None)[0])
        self.assertFalse(evaluate(self.challenge+"\\n",self.good)[0])

    def test_no_serial_result_is_a_vpn_release_credential(self):
        self.assertFalse(release_approved_from_serial("",""))
        self.assertFalse(release_approved_from_serial(self.challenge,self.good))

if __name__=="__main__":
    unittest.main()
