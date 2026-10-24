import unittest
from atlantctl import quota_bytes, AdminError

class QuotaTests(unittest.TestCase):
    def test_fractional_comma_dot_and_zero(self):
        self.assertEqual(107374182, quota_bytes('0.1'))
        self.assertEqual(107374182, quota_bytes('0,1'))
        self.assertEqual(0, quota_bytes('0'))
        self.assertEqual(1073741824, quota_bytes('1'))
    def test_invalid_never_becomes_unlimited(self):
        for value in ['NaN', 'inf', '-1', '0.00000000001', '1e100', 'abc', '1,2,3']:
            with self.subTest(value=value), self.assertRaises(AdminError): quota_bytes(value)
