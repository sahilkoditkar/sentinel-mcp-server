# Sentinel MCP Server

This project provides a lightweight, extensible server built with [FastMCP](https://github.com/intelligent-softworks/fastmcp) that exposes Microsoft Sentinel functionalities as remotely-callable tools. It allows you to query for security incidents and execute KQL queries against your Sentinel Log Analytics workspace.

## Features

- **Get Sentinel Incidents**: Fetch recent security incidents from Microsoft Sentinel.
- **Run KQL Queries**: Execute KQL (Kusto Query Language) queries directly on your Log Analytics workspace.
- **Easy to Deploy**: Runs as a simple Python server.
- **Flexible Authentication**: Supports both Service Principal and Azure CLI-based authentication.

## Directory Structure

The project follows a standard Python application structure:

```
.
├── src/
│   ├── __init__.py
│   ├── mcp_server.py       # The main FastMCP server application
│   └── sentinel_client.py  # Client for interacting with Azure Sentinel APIs
├── tests/
│   └── test_sentinel_client.py # Unit tests for the Sentinel client
├── .env.example            # Example environment variables
├── README.md               # This file
└── requirements.txt        # Python dependencies
```

## Getting Started

### Prerequisites

- Python 3.8+
- An active Azure Subscription with Microsoft Sentinel configured.

### 1. Installation

Clone the repository and install the required Python packages:

```bash
git clone <repository-url>
cd sentinel-mcp-server
pip install -r requirements.txt
```

### 2. Configuration

The server requires Azure credentials to interact with Sentinel. You can authenticate using either a Service Principal or the Azure CLI.

Create a `.env` file in the root directory by copying the example file:

```bash
cp .env.example .env
```

Now, edit the `.env` file with your specific Azure Sentinel details.

**Required Variables:**

- `AZURE_SUBSCRIPTION_ID`: Your Azure subscription ID.
- `AZURE_RESOURCE_GROUP`: The name of the resource group containing your Sentinel workspace.
- `AZURE_WORKSPACE_NAME`: The name of your Log Analytics workspace.
- `AZURE_WORKSPACE_ID`: The unique ID (GUID) of your Log Analytics workspace.

**Authentication:**

You have two options for authentication.

**Option A: Service Principal (Recommended for production)**

For automated workflows, using a Service Principal is the best practice. Add these variables to your `.env` file:

- `AZURE_CLIENT_ID`: The Application (client) ID of your Service Principal.
- `AZURE_CLIENT_SECRET`: The client secret for your Service Principal.
- `AZURE_TENANT_ID`: The Directory (tenant) ID of your Azure Active Directory.

**Option B: Azure CLI (For local development)**

If you are running the server locally, you can authenticate via the Azure CLI. Make sure you are logged in:

```bash
az login
```

The server will automatically use your CLI credentials if the Service Principal variables are not set.

### 3. Usage

To start the MCP server, run the following command from the root directory:

```bash
python src/mcp_server.py
```

The server will start on `http://0.0.0.0:9000` by default. You can now send requests to the available tools.

**Available Tools:**

- **`get_incidents`**: Fetches Sentinel incidents from the last 24 hours.
- **`run_kql_query`**: Executes a KQL query.
  - **Parameter**: `query` (string) - The KQL query to run.

**Example with `curl`:**

```bash
# Get incidents
curl -X POST http://localhost:9000/tool/get_incidents

# Run a KQL query
curl -X POST http://localhost:9000/tool/run_kql_query \
     -H "Content-Type: application/json" \
     -d '{"query": "SecurityIncident | take 5"}'
```

## Running Tests

To run the unit tests for the Sentinel client, execute:

```bash
python -m unittest discover tests
```

This will discover and run all tests located in the `tests` directory.