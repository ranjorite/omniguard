import random
import subprocess

CYPHER_FILE = "init_graph.cypher"
DB_PATH = "omniguard.rl"

def generate_cypher_schema():
    return """
    // 1. Core Framework & Policies (Continuous block so 'reg' and policies bind correctly)
    MERGE (reg:Regulation {name: "PCI DSS v4.0.1"})
    
    // Requirement 3: Stored Data
    MERGE (pol3:Policy {name: "Protect Stored Account Data"})
    MERGE (rule3:Rule {id: "Req 3.3.1.2", name: "SAD is not stored after authorization"})
    MERGE (cde3:DataElement {name: "CVV"})
    MERGE (reg)<-[:references]-(pol3)
    MERGE (pol3)-[:obligation]->(rule3)
    MERGE (rule3)-[:protects]->(cde3)
    
    // Requirement 4: Data in Transit
    MERGE (pol4:Policy {name: "Protect Cardholder Data in Transit"})
    MERGE (rule4:Rule {id: "Req 4.2.1", name: "PAN is protected with strong cryptography during transmission"})
    MERGE (cde4:DataElement {name: "PAN"})
    MERGE (reg)<-[:references]-(pol4)
    MERGE (pol4)-[:obligation]->(rule4)
    MERGE (rule4)-[:protects]->(cde4)
    
    // The Microservices
    MERGE (svc1:Agent {name: "PaymentGatewayAPI", role: "Payment Processor"})
    MERGE (svc2:Agent {name: "Analytics_Export_Job", role: "Internal Data Sync"});
    """

def generate_runtime_logs(num_normal=5):
    cypher_queries = []
    
    for i in range(num_normal):
        log_id = f"LOG_{random.randint(10000, 99999)}"
        cypher_queries.append(f"""
        MATCH (agent:Agent {{name: "PaymentGatewayAPI"}})
        MERGE (log:Usage {{event_id: "{log_id}", type: "AUTH_SUCCESS", payload: "card=****1234, token=tkn_8829"}})
        MERGE (agent)-[:used_by]->(log);
        """)

    cypher_queries.append("""
    MATCH (agent:Agent {name: "PaymentGatewayAPI"})
    MATCH (cde:DataElement {name: "CVV"})
    MERGE (log:Usage {event_id: "LOG_VIOLATION_01", type: "DEBUG_WRITE", payload: "card=****1234, cvv=932, exp=12/28"})
    MERGE (agent)-[:used_by]->(log)
    MERGE (log)-[:exposes]->(cde);
    """)

    cypher_queries.append("""
    MATCH (agent:Agent {name: "Analytics_Export_Job"})
    MATCH (cde:DataElement {name: "PAN"})
    MERGE (log:Usage {event_id: "LOG_VIOLATION_02", type: "API_POST", protocol: "HTTP", payload: "sending cleartext PAN to http://analytics.local/ingest"})
    MERGE (agent)-[:used_by]->(log)
    MERGE (log)-[:exposes]->(cde);
    """)

    return "\n".join(cypher_queries)

def build_database():
    print("Rebuilding OmniGuard Graph Schema...")
    # Remove old database first
    subprocess.run(["powershell", "Remove-Item", DB_PATH, "-ErrorAction", "SilentlyContinue"])
    
    cypher_script = generate_cypher_schema() + "\n" + generate_runtime_logs()
    
    with open(CYPHER_FILE, "w") as f:
        f.write(cypher_script)
    
    try:
        with open(CYPHER_FILE, "r") as f:
            subprocess.run(
                ["relate", "-d", DB_PATH, "query"],
                stdin=f,
                check=True
            )
        print(f"Success! Graph rebuilt and saved to {DB_PATH}")
    except subprocess.CalledProcessError as e:
        print(f"Error executing Relate CLI: {e}")

if __name__ == "__main__":
    build_database()