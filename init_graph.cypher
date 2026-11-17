
    // 1. Core Framework
    MERGE (reg:Regulation {name: "PCI DSS v4.0.1"});
    
    // 2. Requirement 3: Stored Data
    MERGE (pol3:Policy {name: "Protect Stored Account Data"})
    MERGE (rule3:Rule {id: "Req 3.3.1.2", name: "SAD is not stored after authorization"})
    MERGE (cde3:DataElement {name: "CVV"})
    MERGE (reg)<-[:references]-(pol3)-[:obligation]->(rule3)-[:protects]->(cde3);
    
    // 3. Requirement 4: Data in Transit
    MERGE (pol4:Policy {name: "Protect Cardholder Data in Transit"})
    MERGE (rule4:Rule {id: "Req 4.2.1", name: "PAN is protected with strong cryptography during transmission"})
    MERGE (cde4:DataElement {name: "PAN"})
    MERGE (reg)<-[:references]-(pol4)-[:obligation]->(rule4)-[:protects]->(cde4);
    
    // 4. The Microservices
    MERGE (svc1:Agent {name: "PaymentGatewayAPI", role: "Payment Processor"})
    MERGE (svc2:Agent {name: "Analytics_Export_Job", role: "Internal Data Sync"});
    

        MATCH (agent:Agent {name: "PaymentGatewayAPI"})
        MERGE (log:Usage {event_id: "LOG_67724", type: "AUTH_SUCCESS", payload: "card=****1234, token=tkn_8829"})
        MERGE (agent)-[:used_by]->(log);
        

        MATCH (agent:Agent {name: "PaymentGatewayAPI"})
        MERGE (log:Usage {event_id: "LOG_91603", type: "AUTH_SUCCESS", payload: "card=****1234, token=tkn_8829"})
        MERGE (agent)-[:used_by]->(log);
        

        MATCH (agent:Agent {name: "PaymentGatewayAPI"})
        MERGE (log:Usage {event_id: "LOG_58385", type: "AUTH_SUCCESS", payload: "card=****1234, token=tkn_8829"})
        MERGE (agent)-[:used_by]->(log);
        

        MATCH (agent:Agent {name: "PaymentGatewayAPI"})
        MERGE (log:Usage {event_id: "LOG_48062", type: "AUTH_SUCCESS", payload: "card=****1234, token=tkn_8829"})
        MERGE (agent)-[:used_by]->(log);
        

        MATCH (agent:Agent {name: "PaymentGatewayAPI"})
        MERGE (log:Usage {event_id: "LOG_48515", type: "AUTH_SUCCESS", payload: "card=****1234, token=tkn_8829"})
        MERGE (agent)-[:used_by]->(log);
        

    MATCH (agent:Agent {name: "PaymentGatewayAPI"})
    MATCH (cde:DataElement {name: "CVV"})
    MERGE (log:Usage {event_id: "LOG_VIOLATION_01", type: "DEBUG_WRITE", payload: "card=****1234, cvv=932, exp=12/28"})
    MERGE (agent)-[:used_by]->(log)
    MERGE (log)-[:exposes]->(cde);
    

    MATCH (agent:Agent {name: "Analytics_Export_Job"})
    MATCH (cde:DataElement {name: "PAN"})
    MERGE (log:Usage {event_id: "LOG_VIOLATION_02", type: "API_POST", protocol: "HTTP", payload: "sending cleartext PAN to http://analytics.local/ingest"})
    MERGE (agent)-[:used_by]->(log)
    MERGE (log)-[:exposes]->(cde);
    