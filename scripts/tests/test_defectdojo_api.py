import io
import os
from pathlib import Path
import sys
import unittest
import urllib.error
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).parents[1]))
import defectdojo_api as api


class ApiTests(unittest.TestCase):
    def client(self):
        c = api.Client.__new__(api.Client)
        c.base, c.token, c.opener = 'http://127.0.0.1:8080', '', Mock()
        return c

    def test_http_error_is_fatal_without_echoing_body(self):
        c = self.client()
        c.opener.open.side_effect = urllib.error.HTTPError(c.base, 500, 'error', {}, io.BytesIO(b'private response content'))
        with self.assertRaisesRegex(api.DojoError, r'^HTTP 500: POST /api/v2/import-scan/$'):
            c.request('/api/v2/import-scan/', method='POST', fields={})

    def test_network_error_is_fatal_without_echoing_reason(self):
        c = self.client()
        c.opener.open.side_effect = urllib.error.URLError('private connection detail')
        with self.assertRaisesRegex(api.DojoError, r'^Network failure: GET /api/v2/products/$'):
            c.request('/api/v2/products/')

    def test_plain_http_to_non_loopback_is_rejected(self):
        with patch.dict(os.environ, {'DEFECTDOJO_URL': 'http://192.0.2.1:8080'}, clear=True):
            with self.assertRaisesRegex(api.DojoError, 'Plain HTTP allowed only on loopback'):
                api.Client()

    def test_redirect_does_not_forward_authorization(self):
        with self.assertRaisesRegex(api.DojoError, 'Unexpected HTTP redirect'):
            api.NoRedirect().redirect_request(None, None, 302, '', {}, 'https://example.invalid/')

    def test_product_scoped_context_uses_observed_type_id(self):
        c = Mock()
        c.one.side_effect = [{'id': 8, 'prod_type': 12}, {'id': 19, 'product': 8}]
        with patch.dict(os.environ, {'DEFECTDOJO_PRODUCT_TYPE_ID': '12'}):
            self.assertEqual(api.hierarchy(c, False), {'product_type_id': 12, 'product_id': 8, 'engagement_id': 19})
        self.assertEqual([x.args[0] for x in c.one.call_args_list], ['products', 'engagements'])

    def test_context_mismatch_is_fatal(self):
        c = Mock()
        c.one.side_effect = [{'id': 8, 'prod_type': 99}, {'id': 19, 'product': 8}]
        with patch.dict(os.environ, {'DEFECTDOJO_PRODUCT_TYPE_ID': '12'}):
            with self.assertRaisesRegex(api.DojoError, 'Hierarchy identity mismatch'):
                api.hierarchy(c, False)
