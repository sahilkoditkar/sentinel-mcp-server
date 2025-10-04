# sentinel.py
import os
import requests
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

        # print("=== RAW RESPONSE START ===")
        # print(f"Status: {getattr(response, 'status', None)}")
        # print(f"Table count: {len(response.tables)}")

        # for t_index, table in enumerate(response.tables):
        #     print(f"\n-- Table {t_index} --")
        #     print("Columns:", [c.name if hasattr(c, "name") else c for c in table.columns])
        #     print("Rows:")
        #     for row in table.rows:
        #         print(row)
        # print("=== RAW RESPONSE END ===")

        # results = [
        #     dict(zip([c.name if hasattr(c, "name") else c for c in table.columns], row))
        #     for row in table.rows
        # ]

        # The response can contain multiple tables. We'll process the primary one (first table).
        if response.tables:
            table = response.tables[0] # Get the first table

            # 1. Get the column names from the 'columns' attribute of the table object.
            # column_names = [col.name for col in table.columns]
            column_names = [col.name if hasattr(col, "name") else col for col in table.columns]
            
            # 2. Create a list of dictionaries, zipping column names with row values.
            results = [dict(zip(column_names, row)) for row in table.rows]
            
            return results
        else:
            return [] # Return an empty list if there are no tables in the response

    except Exception as e:
        print(f"An error occurred while running KQL query: {e}")
        return {"error": str(e)}


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
