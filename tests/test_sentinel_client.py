import os
import unittest
from unittest.mock import patch, MagicMock
from src import sentinel_client

class TestSentinelClient(unittest.TestCase):

    @patch('src.sentinel_client.ClientSecretCredential')
    @patch('src.sentinel_client.AzureCliCredential')
    def test_get_credentials_sp(self, mock_cli_cred, mock_sp_cred):
        with patch.dict(os.environ, {'AZURE_CLIENT_ID': 'test_id', 'AZURE_CLIENT_SECRET': 'test_secret', 'AZURE_TENANT_ID': 'test_tenant'}):
            sentinel_client.get_credentials()
            mock_sp_cred.assert_called_with(client_id='test_id', client_secret='test_secret', tenant_id='test_tenant')
            mock_cli_cred.assert_not_called()

    @patch('src.sentinel_client.ClientSecretCredential')
    @patch('src.sentinel_client.AzureCliCredential')
    def test_get_credentials_cli(self, mock_cli_cred, mock_sp_cred):
        with patch.dict(os.environ, {}, clear=True):
            sentinel_client.get_credentials()
            mock_cli_cred.assert_called()
            mock_sp_cred.assert_not_called()

    @patch('src.sentinel_client.get_credentials')
    @patch('requests.get')
    def test_get_sentinel_incidents(self, mock_requests_get, mock_get_credentials):
        # Mock credentials and token
        mock_credential = MagicMock()
        mock_credential.get_token.return_value.token = "fake_token"
        mock_get_credentials.return_value = mock_credential

        # Mock response from requests.get
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "value": [
                {
                    "name": "incident1",
                    "properties": {
                        "title": "Test Incident",
                        "status": "New",
                        "severity": "High",
                        "createdTimeUtc": "2023-01-01T00:00:00Z",
                        "description": "This is a test incident."
                    }
                }
            ]
        }
        mock_response.raise_for_status.return_value = None
        mock_requests_get.return_value = mock_response

        # Call the function
        incidents = sentinel_client.get_sentinel_incidents(days=1)

        # Assertions
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]['title'], "Test Incident")
        mock_requests_get.assert_called()

    @patch('src.sentinel_client.get_credentials')
    @patch('src.sentinel_client.LogsQueryClient')
    def test_run_kql_query(self, mock_logs_query_client, mock_get_credentials):
        # Mock credentials
        mock_credential = MagicMock()
        mock_get_credentials.return_value = mock_credential

        # Mock LogsQueryClient
        mock_client_instance = MagicMock()
        mock_logs_query_client.return_value = mock_client_instance

        # Mock response from query_workspace
        mock_table = MagicMock()

        # Correctly mock column objects with a 'name' attribute
        col1 = MagicMock()
        col1.name = 'col1'
        col2 = MagicMock()
        col2.name = 'col2'
        mock_table.columns = [col1, col2]

        mock_table.rows = [['val1', 'val2']]
        mock_response = MagicMock()
        mock_response.tables = [mock_table]
        mock_client_instance.query_workspace.return_value = mock_response

        # Call the function
        query = "SecurityIncident | take 1"
        result = sentinel_client.run_kql_query(query)

        # Assertions
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], {'col1': 'val1', 'col2': 'val2'})
        mock_client_instance.query_workspace.assert_called_with(workspace_id=os.getenv("AZURE_WORKSPACE_ID", ""), query=query, timespan=None)

if __name__ == '__main__':
    unittest.main()