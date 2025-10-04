import os
import unittest
import uuid
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

    @patch('src.sentinel_client.get_credentials')
    @patch('requests.get')
    def test_get_incident_by_id(self, mock_requests_get, mock_get_credentials):
        # Mock credentials and token
        mock_credential = MagicMock()
        mock_credential.get_token.return_value.token = "fake_token"
        mock_get_credentials.return_value = mock_credential

        # Mock response from requests.get
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "name": "incident123",
            "properties": {
                "title": "Specific Test Incident",
                "status": "Active",
                "severity": "Medium",
            }
        }
        mock_response.raise_for_status.return_value = None
        mock_requests_get.return_value = mock_response

        # Call the function
        incident = sentinel_client.get_incident_by_id("incident123")

        # Assertions
        self.assertEqual(incident['title'], "Specific Test Incident")
        self.assertEqual(incident['status'], "Active")
        mock_requests_get.assert_called_once()

    @patch('src.sentinel_client.get_credentials')
    @patch('requests.get')
    def test_get_incident_comments(self, mock_requests_get, mock_get_credentials):
        # Mock credentials and token
        mock_credential = MagicMock()
        mock_credential.get_token.return_value.token = "fake_token"
        mock_get_credentials.return_value = mock_credential

        # Mock response from requests.get
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "value": [
                {
                    "name": "comment1",
                    "properties": {
                        "message": "This is a test comment.",
                        "author": {"name": "Jules"},
                    }
                }
            ]
        }
        mock_response.raise_for_status.return_value = None
        mock_requests_get.return_value = mock_response

        # Call the function
        comments = sentinel_client.get_incident_comments("incident123")

        # Assertions
        self.assertEqual(len(comments), 1)
        self.assertEqual(comments[0]['message'], "This is a test comment.")
        self.assertEqual(comments[0]['author'], "Jules")
        mock_requests_get.assert_called_once()

    @patch('src.sentinel_client.get_credentials')
    @patch('requests.put')
    @patch('requests.get')
    def test_update_incident(self, mock_requests_get, mock_requests_put, mock_get_credentials):
        # Mock credentials and token
        mock_credential = MagicMock()
        mock_credential.get_token.return_value.token = "fake_token"
        mock_get_credentials.return_value = mock_credential

        # Mock GET response (for ETag)
        mock_get_response = MagicMock()
        mock_get_response.json.return_value = {
            "name": "incident123",
            "etag": "\"12345\"",
            "properties": {
                "title": "Initial Title",
                "status": "New",
                "severity": "Low",
            }
        }
        mock_get_response.raise_for_status.return_value = None
        mock_requests_get.return_value = mock_get_response

        # Mock PUT response
        mock_put_response = MagicMock()
        mock_put_response.json.return_value = {
            "name": "incident123",
            "properties": {
                "title": "Initial Title",
                "status": "Active",
                "severity": "High",
            }
        }
        mock_put_response.raise_for_status.return_value = None
        mock_requests_put.return_value = mock_put_response

        # Call the function
        updated_incident = sentinel_client.update_incident("incident123", status="Active", severity="High")

        # Assertions
        mock_requests_get.assert_called_once()
        mock_requests_put.assert_called_once()

        # Check that the ETag was correctly passed in the headers of the PUT request
        headers = mock_requests_put.call_args.kwargs.get('headers')
        self.assertEqual(headers['If-Match'], '"12345"')

        # Check that the payload was correct
        payload = mock_requests_put.call_args.kwargs.get('json')
        self.assertEqual(payload['properties']['status'], 'Active')
        self.assertEqual(payload['properties']['severity'], 'High')

        # Check the final output
        self.assertEqual(updated_incident['properties']['status'], "Active")

    @patch('src.sentinel_client.get_credentials')
    @patch('requests.put')
    @patch('uuid.uuid4')
    def test_add_incident_comment(self, mock_uuid, mock_requests_put, mock_get_credentials):
        # Mock credentials and token
        mock_credential = MagicMock()
        mock_credential.get_token.return_value.token = "fake_token"
        mock_get_credentials.return_value = mock_credential

        # Mock uuid
        mock_uuid.return_value = "comment-uuid"

        # Mock PUT response
        mock_put_response = MagicMock()
        mock_put_response.json.return_value = {
            "name": "comment-uuid",
            "properties": {
                "message": "This is a new comment.",
            }
        }
        mock_put_response.raise_for_status.return_value = None
        mock_requests_put.return_value = mock_put_response

        # Call the function
        new_comment = sentinel_client.add_incident_comment("incident123", "This is a new comment.")

        # Assertions
        mock_requests_put.assert_called_once()

        # Check the URL contains the mocked uuid
        self.assertIn("comment-uuid", mock_requests_put.call_args[0][0])

        # Check that the payload was correct
        payload = mock_requests_put.call_args.kwargs.get('json')
        self.assertEqual(payload['properties']['message'], 'This is a new comment.')

        # Check the final output
        self.assertEqual(new_comment['properties']['message'], "This is a new comment.")

    @patch('src.sentinel_client.get_credentials')
    @patch('requests.post')
    def test_get_incident_alerts(self, mock_requests_post, mock_get_credentials):
        # Mock credentials and token
        mock_credential = MagicMock()
        mock_credential.get_token.return_value.token = "fake_token"
        mock_get_credentials.return_value = mock_credential

        # Mock POST response
        mock_post_response = MagicMock()
        mock_post_response.json.return_value = {
            "value": [
                {"name": "alert1", "properties": {"displayName": "Test Alert 1"}},
                {"name": "alert2", "properties": {"displayName": "Test Alert 2"}},
            ]
        }
        mock_post_response.raise_for_status.return_value = None
        mock_requests_post.return_value = mock_post_response

        # Call the function
        alerts = sentinel_client.get_incident_alerts("incident123")

        # Assertions
        mock_requests_post.assert_called_once()
        self.assertEqual(len(alerts), 2)
        self.assertEqual(alerts[0]['properties']['displayName'], "Test Alert 1")


if __name__ == '__main__':
    unittest.main()