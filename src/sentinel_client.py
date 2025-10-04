# sentinel.py
import os
import requests
import uuid
from datetime import datetime, timedelta, timezone
from azure.identity import (
    ClientSecretCredential,
    AzureCliCredential,
)
from azure.core.credentials import AccessToken
from azure.monitor.query import LogsQueryClient
from azure.monitor.query import LogsQueryStatus
from datetime import timedelta, datetime


# Sentinel config
SUBSCRIPTION_ID = os.getenv("AZURE_SUBSCRIPTION_ID", "")
RESOURCE_GROUP = os.getenv("AZURE_RESOURCE_GROUP", "")
WORKSPACE_NAME = os.getenv("AZURE_WORKSPACE_NAME", "")
WORKSPACE_ID = os.getenv("AZURE_WORKSPACE_ID", "")


def get_credentials():
    """
    Returns an Azure credential object.
    - If AZURE_CLIENT_ID and AZURE_CLIENT_SECRET are set -> Service Principal auth.
    - Else fallback to az login (AzureCliCredential).
    """
    client_id = os.getenv("AZURE_CLIENT_ID")
    client_secret = os.getenv("AZURE_CLIENT_SECRET")
    tenant_id = os.getenv("AZURE_TENANT_ID")

    if client_id and client_secret and tenant_id:
        print("[Auth] Using Service Principal authentication")
        return ClientSecretCredential(
            client_id=client_id,
            client_secret=client_secret,
            tenant_id=tenant_id,
        )

    print("[Auth] Using Azure CLI authentication (az login)")
    return AzureCliCredential()


def get_token(credential):
    """Get a valid bearer token for Azure Management API."""
    token: AccessToken = credential.get_token("https://management.azure.com/.default")
    return token.token


def run_kql_query(query: str, timespan: timedelta = None):
    """
    Run a KQL query against the Sentinel Log Analytics workspace.
    Args:
        query (str): The KQL query string.
        timespan (str): None, to control it from query.
    Returns:
        dict: { "tables": [ { "name": "TableName", "rows": [...], "columns": [...] } ] }
    """
    try:
        credential = get_credentials()
        client = LogsQueryClient(credential)

        response = client.query_workspace(
            workspace_id=WORKSPACE_ID,  # Workspace GUID, not name
            query=query,
            timespan=None,
        )

        if response.tables:
            table = response.tables[0]
            column_names = [col.name if hasattr(col, "name") else col for col in table.columns]
            results = [dict(zip(column_names, row)) for row in table.rows]
            return results
        else:
            return []

    except Exception as e:
        print(f"An error occurred while running KQL query: {e}")
        return {"error": str(e)}


def get_sentinel_incidents(days=1):
    """
    Fetch Sentinel incidents from the last `days` days.
    Default = last 24h.
    """
    credential = get_credentials()
    token = get_token(credential)

    since = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")

    url = (
        f"https://management.azure.com/subscriptions/{SUBSCRIPTION_ID}"
        f"/resourceGroups/{RESOURCE_GROUP}/providers/Microsoft.OperationalInsights/workspaces/{WORKSPACE_NAME}"
        f"/providers/Microsoft.SecurityInsights/incidents"
        f"?api-version=2023-09-01-preview"
        f"&$filter=properties/createdTimeUtc ge {since}"
    )

    headers = {"Authorization": f"Bearer {token}"}
    resp = requests.get(url, headers=headers)
    resp.raise_for_status()

    data = resp.json()
    results = []
    for item in data.get("value", []):
        props = item.get("properties", {})
        results.append(
            {
                "id": item.get("name"),
                "title": props.get("title"),
                "status": props.get("status"),
                "severity": props.get("severity"),
                "createdTimeUtc": props.get("createdTimeUtc"),
                "description": props.get("description"),
            }
        )

    # handle pagination if nextLink exists
    next_link = data.get("nextLink")
    while next_link:
        resp = requests.get(next_link, headers=headers)
        resp.raise_for_status()
        data = resp.json()
        for item in data.get("value", []):
            props = item.get("properties", {})
            results.append(
                {
                    "id": item.get("name"),
                    "title": props.get("title"),
                    "status": props.get("status"),
                    "severity": props.get("severity"),
                    "createdTimeUtc": props.get("createdTimeUtc"),
                    "description": props.get("description"),
                }
            )
        next_link = data.get("nextLink")

    return results


def get_incident_by_id(incident_id: str):
    """
    Fetch a single Sentinel incident by its ID.
    """
    credential = get_credentials()
    token = get_token(credential)

    url = (
        f"https://management.azure.com/subscriptions/{SUBSCRIPTION_ID}"
        f"/resourceGroups/{RESOURCE_GROUP}/providers/Microsoft.OperationalInsights/workspaces/{WORKSPACE_NAME}"
        f"/providers/Microsoft.SecurityInsights/incidents/{incident_id}"
        f"?api-version=2023-09-01-preview"
    )

    headers = {"Authorization": f"Bearer {token}"}
    resp = requests.get(url, headers=headers)
    resp.raise_for_status()

    data = resp.json()
    props = data.get("properties", {})
    return {
        "id": data.get("name"),
        "title": props.get("title"),
        "status": props.get("status"),
        "severity": props.get("severity"),
        "createdTimeUtc": props.get("createdTimeUtc"),
        "description": props.get("description"),
        "owner": props.get("owner"),
        "labels": props.get("labels"),
        "firstActivityTimeUtc": props.get("firstActivityTimeUtc"),
        "lastActivityTimeUtc": props.get("lastActivityTimeUtc"),
    }


def update_incident(incident_id: str, status: str = None, severity: str = None, owner: dict = None):
    """
    Update a Sentinel incident.
    """
    credential = get_credentials()
    token = get_token(credential)

    # First, get the existing incident to get the ETag
    get_url = (
        f"https://management.azure.com/subscriptions/{SUBSCRIPTION_ID}"
        f"/resourceGroups/{RESOURCE_GROUP}/providers/Microsoft.OperationalInsights/workspaces/{WORKSPACE_NAME}"
        f"/providers/Microsoft.SecurityInsights/incidents/{incident_id}"
        f"?api-version=2023-09-01-preview"
    )
    headers = {"Authorization": f"Bearer {token}"}
    get_resp = requests.get(get_url, headers=headers)
    get_resp.raise_for_status()
    incident_data = get_resp.json()
    etag = incident_data.get("etag")

    # Prepare the update payload
    update_payload = incident_data["properties"]
    if status:
        update_payload["status"] = status
    if severity:
        update_payload["severity"] = severity
    if owner:
        update_payload["owner"] = owner

    put_url = get_url  # The URL for PUT is the same as for GET
    headers["If-Match"] = etag  # Use the ETag for concurrency control
    put_resp = requests.put(put_url, headers=headers, json={"properties": update_payload})
    put_resp.raise_for_status()

    return put_resp.json()


def get_incident_comments(incident_id: str):
    """
    Fetch comments for a given Sentinel incident.
    """
    credential = get_credentials()
    token = get_token(credential)

    url = (
        f"https://management.azure.com/subscriptions/{SUBSCRIPTION_ID}"
        f"/resourceGroups/{RESOURCE_GROUP}/providers/Microsoft.OperationalInsights/workspaces/{WORKSPACE_NAME}"
        f"/providers/Microsoft.SecurityInsights/incidents/{incident_id}/comments"
        f"?api-version=2023-09-01-preview"
    )

    headers = {"Authorization": f"Bearer {token}"}
    resp = requests.get(url, headers=headers)
    resp.raise_for_status()

    data = resp.json()
    results = []
    for item in data.get("value", []):
        props = item.get("properties", {})
        results.append(
            {
                "id": item.get("name"),
                "author": props.get("author", {}).get("name"),
                "message": props.get("message"),
                "createdTimeUtc": props.get("createdTimeUtc"),
            }
        )
    return results


def add_incident_comment(incident_id: str, message: str):
    """
    Add a comment to a Sentinel incident.
    """
    credential = get_credentials()
    token = get_token(credential)
    comment_id = str(uuid.uuid4())

    url = (
        f"https://management.azure.com/subscriptions/{SUBSCRIPTION_ID}"
        f"/resourceGroups/{RESOURCE_GROUP}/providers/Microsoft.OperationalInsights/workspaces/{WORKSPACE_NAME}"
        f"/providers/Microsoft.SecurityInsights/incidents/{incident_id}/comments/{comment_id}"
        f"?api-version=2023-09-01-preview"
    )

    headers = {"Authorization": f"Bearer {token}"}
    payload = {"properties": {"message": message}}
    resp = requests.put(url, headers=headers, json=payload)
    resp.raise_for_status()

    return resp.json()


def get_incident_alerts(incident_id: str):
    """
    Get alerts for a given Sentinel incident.
    """
    credential = get_credentials()
    token = get_token(credential)

    url = (
        f"https://management.azure.com/subscriptions/{SUBSCRIPTION_ID}"
        f"/resourceGroups/{RESOURCE_GROUP}/providers/Microsoft.OperationalInsights/workspaces/{WORKSPACE_NAME}"
        f"/providers/Microsoft.SecurityInsights/incidents/{incident_id}/alerts"
        f"?api-version=2023-09-01-preview"
    )

    headers = {"Authorization": f"Bearer {token}"}
    resp = requests.post(url, headers=headers)
    resp.raise_for_status()

    data = resp.json()
    return data.get("value", [])


if __name__ == "__main__":
    # Testing
    # print(get_sentinel_incidents(days=1))
    test_query = """
    SigninLogs
    | where TimeGenerated >= ago(24h)
    | project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, ResultType
    | take 5
    """
    results = run_kql_query(test_query, timespan=timedelta(days=1))
    print(results)