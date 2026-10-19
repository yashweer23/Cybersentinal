# Five generated Phase 4 events

These complete records were extracted from the verified 1,000-event JSONL file (`--count 1000 --seed 42 --scenario mixed`, default date and run ID). They conform to the existing `SecurityEventCreate` schema. The examples represent different scenarios rather than the first five lines of the chronological file.

## 1. normal_activity

```json
{
  "event_id": "EVT-3fee0d92-28b5-59fc-a24f-e0724477cc45",
  "timestamp": "2026-09-26T03:07:56Z",
  "source_ip": "10.0.1.22",
  "destination_ip": "10.0.10.10",
  "username": "employee022",
  "event_type": "LOGIN_SUCCESS",
  "service": "authentication",
  "source_port": 62359,
  "destination_port": 443,
  "country": "India",
  "device": "LT-CHE-022",
  "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/128.0.0.0 Safari/537.36",
  "status": "success",
  "raw_data": {
    "environment": "simulation",
    "geo": {
      "city": "Chennai",
      "country": "India",
      "latitude": 13.0827,
      "longitude": 80.2707
    },
    "destination_device": "SRV-AUTH-01",
    "simulation": {
      "scenario": "normal_activity",
      "scenario_id": "SIM-32047406-9081-5b31-a801-dea5901be77e",
      "generator_version": "1",
      "run_id": "demo"
    }
  }
}
```

## 2. brute_force

```json
{
  "event_id": "EVT-06e81d27-7e32-5527-8788-d9ab2c762bdd",
  "timestamp": "2026-09-26T04:19:07Z",
  "source_ip": "198.51.100.46",
  "destination_ip": "10.0.10.10",
  "username": "employee089",
  "event_type": "LOGIN_FAILED",
  "service": "authentication",
  "source_port": 59965,
  "destination_port": 443,
  "country": "India",
  "device": "WS-EXTERNAL-SIM",
  "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/128.0.0.0 Safari/537.36",
  "status": "failed",
  "raw_data": {
    "environment": "simulation",
    "geo": {
      "city": "Mumbai",
      "country": "India",
      "latitude": 19.076,
      "longitude": 72.8777
    },
    "destination_device": "SRV-AUTH-01",
    "authentication_method": "password",
    "simulation": {
      "scenario": "brute_force",
      "scenario_id": "SIM-f2fddd8f-9511-515f-9294-d036185d22de",
      "generator_version": "1",
      "run_id": "demo"
    }
  }
}
```

## 3. password_spray

```json
{
  "event_id": "EVT-9e670dd9-9dc1-5f45-9459-58846d6899fb",
  "timestamp": "2026-10-02T08:14:50Z",
  "source_ip": "198.51.100.117",
  "destination_ip": "10.0.10.10",
  "username": "employee050",
  "event_type": "LOGIN_FAILED",
  "service": "authentication",
  "source_port": 56142,
  "destination_port": 443,
  "country": "India",
  "device": "WS-EXTERNAL-SIM",
  "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/128.0.0.0 Safari/537.36",
  "status": "failed",
  "raw_data": {
    "environment": "simulation",
    "geo": {
      "city": "Chennai",
      "country": "India",
      "latitude": 13.0827,
      "longitude": 80.2707
    },
    "destination_device": "SRV-AUTH-01",
    "authentication_method": "password",
    "simulation": {
      "scenario": "password_spray",
      "scenario_id": "SIM-921c3fad-8128-5d2c-91e9-4e11d9a2a648",
      "generator_version": "1",
      "run_id": "demo"
    }
  }
}
```

## 4. impossible_travel

```json
{
  "event_id": "EVT-6f00ab62-b185-575c-ade1-7d8fecea9816",
  "timestamp": "2026-09-30T06:03:47Z",
  "source_ip": "10.0.1.5",
  "destination_ip": "10.0.10.10",
  "username": "employee005",
  "event_type": "LOGIN_SUCCESS",
  "service": "authentication",
  "source_port": 50404,
  "destination_port": 443,
  "country": "India",
  "device": "LT-DEL-005",
  "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:129.0) Gecko/20100101 Firefox/129.0",
  "status": "success",
  "raw_data": {
    "environment": "simulation",
    "geo": {
      "city": "Delhi",
      "country": "India",
      "latitude": 28.6139,
      "longitude": 77.209
    },
    "destination_device": "SRV-AUTH-01",
    "simulation": {
      "scenario": "impossible_travel",
      "scenario_id": "SIM-9ea92712-3c59-5be2-85d4-149c646f8e1f",
      "generator_version": "1",
      "run_id": "demo"
    }
  }
}
```

## 5. excessive_access

```json
{
  "event_id": "EVT-0c46f790-4e89-5053-8a01-bce87d6b4703",
  "timestamp": "2026-09-28T04:26:09Z",
  "source_ip": "10.0.1.64",
  "destination_ip": "10.0.10.15",
  "username": "employee064",
  "event_type": "SENSITIVE_RECORD_ACCESS",
  "service": "records-api",
  "source_port": 49208,
  "destination_port": 443,
  "country": "India",
  "device": "LT-DEL-064",
  "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0",
  "status": "success",
  "raw_data": {
    "environment": "simulation",
    "geo": {
      "city": "Delhi",
      "country": "India",
      "latitude": 28.6139,
      "longitude": 77.209
    },
    "destination_device": "SRV-API-01",
    "resource_type": "patient_record",
    "department": "simulated",
    "sensitive": true,
    "record_id": "REC-25a8b6e310775ecb943f9a521096c222-000001",
    "record_ids": [
      "REC-25a8b6e310775ecb943f9a521096c222-000001",
      "REC-25a8b6e310775ecb943f9a521096c222-000002",
      "REC-25a8b6e310775ecb943f9a521096c222-000003",
      "REC-25a8b6e310775ecb943f9a521096c222-000004",
      "REC-25a8b6e310775ecb943f9a521096c222-000005",
      "REC-25a8b6e310775ecb943f9a521096c222-000006",
      "REC-25a8b6e310775ecb943f9a521096c222-000007",
      "REC-25a8b6e310775ecb943f9a521096c222-000008",
      "REC-25a8b6e310775ecb943f9a521096c222-000009",
      "REC-25a8b6e310775ecb943f9a521096c222-000010",
      "REC-25a8b6e310775ecb943f9a521096c222-000011",
      "REC-25a8b6e310775ecb943f9a521096c222-000012",
      "REC-25a8b6e310775ecb943f9a521096c222-000013",
      "REC-25a8b6e310775ecb943f9a521096c222-000014",
      "REC-25a8b6e310775ecb943f9a521096c222-000015",
      "REC-25a8b6e310775ecb943f9a521096c222-000016",
      "REC-25a8b6e310775ecb943f9a521096c222-000017",
      "REC-25a8b6e310775ecb943f9a521096c222-000018",
      "REC-25a8b6e310775ecb943f9a521096c222-000019",
      "REC-25a8b6e310775ecb943f9a521096c222-000020",
      "REC-25a8b6e310775ecb943f9a521096c222-000021",
      "REC-25a8b6e310775ecb943f9a521096c222-000022",
      "REC-25a8b6e310775ecb943f9a521096c222-000023",
      "REC-25a8b6e310775ecb943f9a521096c222-000024",
      "REC-25a8b6e310775ecb943f9a521096c222-000025"
    ],
    "record_count": 25,
    "simulation": {
      "scenario": "excessive_access",
      "scenario_id": "SIM-25a8b6e3-1077-5ecb-943f-9a521096c222",
      "generator_version": "1",
      "run_id": "demo"
    }
  }
}
```

The excessive-access example describes 25 fictional records in one log. Its full scenario contains 20 such logs and 500 distinct record IDs over 20 minutes. The full impossible-travel scenario contains two successful logins for the same user with different geo coordinates. Ground-truth labels must not be used as detection evidence.
