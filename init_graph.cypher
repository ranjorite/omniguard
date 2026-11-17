
    // 1. Core Framework
    MERGE (reg:Regulation {name: "PCI DSS v4.0.1"})
    
    // 2. Requirement 3: Stored Data (From Trainer Notes)
    MERGE (pol3:Policy {name: "Protect Stored Account Data"})
    MERGE (rule3:Rule {id: "Req 3.3.1.2", name: "SAD is not stored after authorization"})
    MERGE (cde3:DataElement {name: "CVV"})
    MERGE (reg)<-[:references]-(pol3)-[:obligation]->(rule3)-[:protects]->(cde3)
    
    // 3. Requirement 4: Data in Transit (From Trainer Notes)
    MERGE (pol4:Policy {name: "Protect Cardholder Data in Transit"})
    MERGE (rule4:Rule {id: "Req 4.2.1", name: "PAN is protected with strong cryptography during transmission"})
    MERGE (cde4:DataElement {name: "PAN"})
    MERGE (reg)<-[:references]-(pol4)-[:obligation]->(rule4)-[:protects]->(cde4)
    
    // 4. The Microservices
    MERGE (svc1:Agent {name: "PaymentGatewayAPI", role: "Payment Processor"})
    MERGE (svc2:Agent {name: "Analytics_Export_Job", role: "Internal Data Sync"})
    

        MATCH (agent:Agent {name: "PaymentGatewayAPI"})
        MERGE (log:Usage {event_id: "LOG_45282", type: "AUTH_SUCCESS", payload: "card=****1234, token=tkn_8829"})
        MERGE (agent)-[:used_by]->(log)
        

        MATCH (agent:Agent {name: "PaymentGatewayAPI"})
        MERGE (log:Usage {event_id: "LOG_24340", type: "AUTH_SUCCESS", payload: "card=****1234, token=tkn_8829"})
        MERGE (agent)-[:used_by]->(log)
        

        MATCH (agent:Agent {name: "PaymentGatewayAPI"})
        MERGE (log:Usage {event_id: "LOG_94790", type: "AUTH_SUCCESS", payload: "card=****1234, token=tkn_8829"})
        MERGE (agent)-[:used_by]->(log)
        

        MATCH (agent:Agent {name: "PaymentGatewayAPI"})
        MERGE (log:Usage {event_id: "LOG_59147", type: "AUTH_SUCCESS", payload: "card=****1234, token=tkn_8829"})
        MERGE (agent)-[:used_by]->(log)
        

        MATCH (agent:Agent {name: "PaymentGatewayAPI"})
        MERGE (log:Usage {event_id: "LOG_54022", type: "AUTH_SUCCESS", payload: "card=****1234, token=tkn_8829"})
        MERGE (agent)-[:used_by]->(log)
        

        MATCH (agent:Agent {name: "PaymentGatewayAPI"})
        MERGE (log:Usage {event_id: "LOG_17026", type: "AUTH_SUCCESS", payload: "card=****1234, token=tkn_8829"})
        MERGE (agent)-[:used_by]->(log)
        

        MATCH (agent:Agent {name: "PaymentGatewayAPI"})
        MERGE (log:Usage {event_id: "LOG_29330", type: "AUTH_SUCCESS", payload: "card=****1234, token=tkn_8829"})
        MERGE (agent)-[:used_by]->(log)
        

        MATCH (agent:Agent {name: "PaymentGatewayAPI"})
        MERGE (log:Usage {event_id: "LOG_32639", type: "AUTH_SUCCESS", payload: "card=****1234, token=tkn_8829"})
        MERGE (agent)-[:used_by]->(log)
        

        MATCH (agent:Agent {name: "PaymentGatewayAPI"})
        MERGE (log:Usage {event_id: "LOG_50958", type: "AUTH_SUCCESS", payload: "card=****1234, token=tkn_8829"})
        MERGE (agent)-[:used_by]->(log)
        

        MATCH (agent:Agent {name: "PaymentGatewayAPI"})
        MERGE (log:Usage {event_id: "LOG_99742", type: "AUTH_SUCCESS", payload: "card=****1234, token=tkn_8829"})
        MERGE (agent)-[:used_by]->(log)
        

        MATCH (agent:Agent {name: "PaymentGatewayAPI"})
        MERGE (log:Usage {event_id: "LOG_56117", type: "AUTH_SUCCESS", payload: "card=****1234, token=tkn_8829"})
        MERGE (agent)-[:used_by]->(log)
        

        MATCH (agent:Agent {name: "PaymentGatewayAPI"})
        MERGE (log:Usage {event_id: "LOG_34763", type: "AUTH_SUCCESS", payload: "card=****1234, token=tkn_8829"})
        MERGE (agent)-[:used_by]->(log)
        

        MATCH (agent:Agent {name: "PaymentGatewayAPI"})
        MERGE (log:Usage {event_id: "LOG_99107", type: "AUTH_SUCCESS", payload: "card=****1234, token=tkn_8829"})
        MERGE (agent)-[:used_by]->(log)
        

        MATCH (agent:Agent {name: "PaymentGatewayAPI"})
        MERGE (log:Usage {event_id: "LOG_76857", type: "AUTH_SUCCESS", payload: "card=****1234, token=tkn_8829"})
        MERGE (agent)-[:used_by]->(log)
        

        MATCH (agent:Agent {name: "PaymentGatewayAPI"})
        MERGE (log:Usage {event_id: "LOG_18973", type: "AUTH_SUCCESS", payload: "card=****1234, token=tkn_8829"})
        MERGE (agent)-[:used_by]->(log)
        

        MATCH (agent:Agent {name: "PaymentGatewayAPI"})
        MERGE (log:Usage {event_id: "LOG_41803", type: "AUTH_SUCCESS", payload: "card=****1234, token=tkn_8829"})
        MERGE (agent)-[:used_by]->(log)
        

        MATCH (agent:Agent {name: "PaymentGatewayAPI"})
        MERGE (log:Usage {event_id: "LOG_57672", type: "AUTH_SUCCESS", payload: "card=****1234, token=tkn_8829"})
        MERGE (agent)-[:used_by]->(log)
        

        MATCH (agent:Agent {name: "PaymentGatewayAPI"})
        MERGE (log:Usage {event_id: "LOG_55436", type: "AUTH_SUCCESS", payload: "card=****1234, token=tkn_8829"})
        MERGE (agent)-[:used_by]->(log)
        

        MATCH (agent:Agent {name: "PaymentGatewayAPI"})
        MERGE (log:Usage {event_id: "LOG_89723", type: "AUTH_SUCCESS", payload: "card=****1234, token=tkn_8829"})
        MERGE (agent)-[:used_by]->(log)
        

        MATCH (agent:Agent {name: "PaymentGatewayAPI"})
        MERGE (log:Usage {event_id: "LOG_85470", type: "AUTH_SUCCESS", payload: "card=****1234, token=tkn_8829"})
        MERGE (agent)-[:used_by]->(log)
        

        MATCH (agent:Agent {name: "PaymentGatewayAPI"})
        MERGE (log:Usage {event_id: "LOG_59067", type: "AUTH_SUCCESS", payload: "card=****1234, token=tkn_8829"})
        MERGE (agent)-[:used_by]->(log)
        

        MATCH (agent:Agent {name: "PaymentGatewayAPI"})
        MERGE (log:Usage {event_id: "LOG_40067", type: "AUTH_SUCCESS", payload: "card=****1234, token=tkn_8829"})
        MERGE (agent)-[:used_by]->(log)
        

        MATCH (agent:Agent {name: "PaymentGatewayAPI"})
        MERGE (log:Usage {event_id: "LOG_86002", type: "AUTH_SUCCESS", payload: "card=****1234, token=tkn_8829"})
        MERGE (agent)-[:used_by]->(log)
        

        MATCH (agent:Agent {name: "PaymentGatewayAPI"})
        MERGE (log:Usage {event_id: "LOG_51434", type: "AUTH_SUCCESS", payload: "card=****1234, token=tkn_8829"})
        MERGE (agent)-[:used_by]->(log)
        

        MATCH (agent:Agent {name: "PaymentGatewayAPI"})
        MERGE (log:Usage {event_id: "LOG_14334", type: "AUTH_SUCCESS", payload: "card=****1234, token=tkn_8829"})
        MERGE (agent)-[:used_by]->(log)
        

        MATCH (agent:Agent {name: "PaymentGatewayAPI"})
        MERGE (log:Usage {event_id: "LOG_86740", type: "AUTH_SUCCESS", payload: "card=****1234, token=tkn_8829"})
        MERGE (agent)-[:used_by]->(log)
        

        MATCH (agent:Agent {name: "PaymentGatewayAPI"})
        MERGE (log:Usage {event_id: "LOG_69933", type: "AUTH_SUCCESS", payload: "card=****1234, token=tkn_8829"})
        MERGE (agent)-[:used_by]->(log)
        

        MATCH (agent:Agent {name: "PaymentGatewayAPI"})
        MERGE (log:Usage {event_id: "LOG_11993", type: "AUTH_SUCCESS", payload: "card=****1234, token=tkn_8829"})
        MERGE (agent)-[:used_by]->(log)
        

        MATCH (agent:Agent {name: "PaymentGatewayAPI"})
        MERGE (log:Usage {event_id: "LOG_20304", type: "AUTH_SUCCESS", payload: "card=****1234, token=tkn_8829"})
        MERGE (agent)-[:used_by]->(log)
        

        MATCH (agent:Agent {name: "PaymentGatewayAPI"})
        MERGE (log:Usage {event_id: "LOG_43034", type: "AUTH_SUCCESS", payload: "card=****1234, token=tkn_8829"})
        MERGE (agent)-[:used_by]->(log)
        

        MATCH (agent:Agent {name: "PaymentGatewayAPI"})
        MERGE (log:Usage {event_id: "LOG_78115", type: "AUTH_SUCCESS", payload: "card=****1234, token=tkn_8829"})
        MERGE (agent)-[:used_by]->(log)
        

        MATCH (agent:Agent {name: "PaymentGatewayAPI"})
        MERGE (log:Usage {event_id: "LOG_79782", type: "AUTH_SUCCESS", payload: "card=****1234, token=tkn_8829"})
        MERGE (agent)-[:used_by]->(log)
        

        MATCH (agent:Agent {name: "PaymentGatewayAPI"})
        MERGE (log:Usage {event_id: "LOG_17655", type: "AUTH_SUCCESS", payload: "card=****1234, token=tkn_8829"})
        MERGE (agent)-[:used_by]->(log)
        

        MATCH (agent:Agent {name: "PaymentGatewayAPI"})
        MERGE (log:Usage {event_id: "LOG_35666", type: "AUTH_SUCCESS", payload: "card=****1234, token=tkn_8829"})
        MERGE (agent)-[:used_by]->(log)
        

        MATCH (agent:Agent {name: "PaymentGatewayAPI"})
        MERGE (log:Usage {event_id: "LOG_64102", type: "AUTH_SUCCESS", payload: "card=****1234, token=tkn_8829"})
        MERGE (agent)-[:used_by]->(log)
        

        MATCH (agent:Agent {name: "PaymentGatewayAPI"})
        MERGE (log:Usage {event_id: "LOG_78935", type: "AUTH_SUCCESS", payload: "card=****1234, token=tkn_8829"})
        MERGE (agent)-[:used_by]->(log)
        

        MATCH (agent:Agent {name: "PaymentGatewayAPI"})
        MERGE (log:Usage {event_id: "LOG_27000", type: "AUTH_SUCCESS", payload: "card=****1234, token=tkn_8829"})
        MERGE (agent)-[:used_by]->(log)
        

        MATCH (agent:Agent {name: "PaymentGatewayAPI"})
        MERGE (log:Usage {event_id: "LOG_92296", type: "AUTH_SUCCESS", payload: "card=****1234, token=tkn_8829"})
        MERGE (agent)-[:used_by]->(log)
        

        MATCH (agent:Agent {name: "PaymentGatewayAPI"})
        MERGE (log:Usage {event_id: "LOG_54290", type: "AUTH_SUCCESS", payload: "card=****1234, token=tkn_8829"})
        MERGE (agent)-[:used_by]->(log)
        

        MATCH (agent:Agent {name: "PaymentGatewayAPI"})
        MERGE (log:Usage {event_id: "LOG_48838", type: "AUTH_SUCCESS", payload: "card=****1234, token=tkn_8829"})
        MERGE (agent)-[:used_by]->(log)
        

        MATCH (agent:Agent {name: "PaymentGatewayAPI"})
        MERGE (log:Usage {event_id: "LOG_34312", type: "AUTH_SUCCESS", payload: "card=****1234, token=tkn_8829"})
        MERGE (agent)-[:used_by]->(log)
        

        MATCH (agent:Agent {name: "PaymentGatewayAPI"})
        MERGE (log:Usage {event_id: "LOG_43524", type: "AUTH_SUCCESS", payload: "card=****1234, token=tkn_8829"})
        MERGE (agent)-[:used_by]->(log)
        

        MATCH (agent:Agent {name: "PaymentGatewayAPI"})
        MERGE (log:Usage {event_id: "LOG_11215", type: "AUTH_SUCCESS", payload: "card=****1234, token=tkn_8829"})
        MERGE (agent)-[:used_by]->(log)
        

        MATCH (agent:Agent {name: "PaymentGatewayAPI"})
        MERGE (log:Usage {event_id: "LOG_24740", type: "AUTH_SUCCESS", payload: "card=****1234, token=tkn_8829"})
        MERGE (agent)-[:used_by]->(log)
        

        MATCH (agent:Agent {name: "PaymentGatewayAPI"})
        MERGE (log:Usage {event_id: "LOG_89191", type: "AUTH_SUCCESS", payload: "card=****1234, token=tkn_8829"})
        MERGE (agent)-[:used_by]->(log)
        

        MATCH (agent:Agent {name: "PaymentGatewayAPI"})
        MERGE (log:Usage {event_id: "LOG_38549", type: "AUTH_SUCCESS", payload: "card=****1234, token=tkn_8829"})
        MERGE (agent)-[:used_by]->(log)
        

        MATCH (agent:Agent {name: "PaymentGatewayAPI"})
        MERGE (log:Usage {event_id: "LOG_24993", type: "AUTH_SUCCESS", payload: "card=****1234, token=tkn_8829"})
        MERGE (agent)-[:used_by]->(log)
        

        MATCH (agent:Agent {name: "PaymentGatewayAPI"})
        MERGE (log:Usage {event_id: "LOG_35825", type: "AUTH_SUCCESS", payload: "card=****1234, token=tkn_8829"})
        MERGE (agent)-[:used_by]->(log)
        

        MATCH (agent:Agent {name: "PaymentGatewayAPI"})
        MERGE (log:Usage {event_id: "LOG_24917", type: "AUTH_SUCCESS", payload: "card=****1234, token=tkn_8829"})
        MERGE (agent)-[:used_by]->(log)
        

        MATCH (agent:Agent {name: "PaymentGatewayAPI"})
        MERGE (log:Usage {event_id: "LOG_65578", type: "AUTH_SUCCESS", payload: "card=****1234, token=tkn_8829"})
        MERGE (agent)-[:used_by]->(log)
        

    MATCH (agent:Agent {name: "PaymentGatewayAPI"})
    MATCH (cde:DataElement {name: "CVV"})
    MERGE (log:Usage {event_id: "LOG_VIOLATION_01", type: "DEBUG_WRITE", payload: "card=****1234, cvv=932, exp=12/28"})
    MERGE (agent)-[:used_by]->(log)
    MERGE (log)-[:exposes]->(cde)
    

    MATCH (agent:Agent {name: "Analytics_Export_Job"})
    MATCH (cde:DataElement {name: "PAN"})
    MERGE (log:Usage {event_id: "LOG_VIOLATION_02", type: "API_POST", protocol: "HTTP", payload: "sending cleartext PAN to http://analytics.local/ingest"})
    MERGE (agent)-[:used_by]->(log)
    MERGE (log)-[:exposes]->(cde)
    