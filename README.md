\# OmniGuard: CDMC Graph Forensics

An embedded Relate graph agent that implements the official EDM Council CDMC metamodel. It connects runtime logs to regulatory ontologies to instantly trace PCI DSS violations and blast radius.



\## Use case

When Sensitive Authentication Data (SAD) like a CVV leaks in an application log, or a Primary Account Number (PAN) is transmitted without encryption, flat log scanners cannot trace the leak back to the governing compliance rule. OmniGuard solves this by unifying runtime logs and the official EDM Council CDMC Information Metamodel into a single graph. When an AI agent detects a leak, it traverses the multi-hop relationships to identify exactly which PCI DSS v4.0.1 Requirement (e.g., Req 3.3.1.2 or Req 4.2.1) was violated and by which microservice.



\## How it uses Relate

\- \*\*Mode:\*\* single file

\- \*\*Why this mode:\*\* We chose Single File mode so the entire populated CDMC governance graph and log history ships as a portable, zero-configuration artifact. Security agents and Devpost judges can clone the repository, inspect the data, and query it in-process immediately via MCP without standing up external database infrastructure.

\- \*\*What the graph models:\*\* The graph strictly implements the EDM Council CDMC v1.1 Information Metamodel. It models top-level governance (`:Regulation`, `:Policy`, `:Rule`, `:DataElement`) connected directly to runtime application events (`:Agent`, `:Usage`). 



\## Setup and run

\*\*Prerequisites:\*\* 

\- Python 3.9+

\- Relate CLI v0.1.3+ (`curl -sSfL https://relatedb.ai/install.sh | bash`)

\- An MCP-compatible AI Agent (e.g., Claude Desktop, Cursor)



\*\*1. Generate the Graph and Synthetic Logs\*\*

Run the ingestion script to build the CDMC ontology and inject the PCI DSS log violations into the Relate database:

```bash

python seed\_graph.py

