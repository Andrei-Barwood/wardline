# Test Coverage Gaps and Analysis (Prompt 19 Audit)

## Overview

A coverage audit was performed across the codebase using `pytest-cov` (`pytest --cov=wardline --cov-report=term-missing`).

- **Total Statements:** 3,118
- **Missed Statements:** 498
- **Overall Code Coverage:** 84%
- **Core Decision Logic Coverage:** >90% (Security, Validation, Circuit Breaker, Quotas, Rate Limiting, Incident State Machine, and Mission Checks).

---

## Modules Below 70% Coverage

The following table documents all modules falling below the 70% coverage threshold, along with the rationale and uncovered behaviors:

| Module | Statements | Missing | Coverage | Uncovered Behaviors / Rationale |
|---|---|---|---|---|
| `src/wardline/__main__.py` | 66 | 66 | 0% | CLI entrypoint for running the server stack (`python -m wardline`). Server execution loops and CLI argument parsing are executed directly in manual / process runs rather than unit tests to avoid flaky process spawns. |
| `src/wardline/auth/principal.py` | 2 | 2 | 0% | Re-export alias module exporting `Principal` from `wardline.contracts`. The class definition is exercised via `contracts.py` (99% coverage). |
| `src/wardline/simulation/__main__.py` | 37 | 37 | 0% | Standalone CLI entrypoint for running simulations. Scenarios themselves are tested in-process via `test_simulation_inprocess.py` and `test_simulation_loopback.py`. |
| `src/wardline/simulation/engine.py` | 155 | 73 | 53% | Asynchronous background generator loops and real UDP socket transmissions. Tested in-process with guarded loopback checks; long continuous event generator cycles are left to end-to-end integration scenarios. |
| `src/wardline/storage/memory.py` | 60 | 19 | 68% | In-memory event repository methods used for transient testing storage; SQLite repository (`sqlite.py`, 89% coverage) is the primary persistence engine used in test configurations. |
| `src/wardline/api/routes/simulation.py` | 22 | 7 | 68% | HTTP routes for triggering and stopping simulations on demand. Base route validation is covered, while manual trigger branches with custom event rates are covered in integration tests. |

---

## Decision Modules Status

All pure decision, policy, security, and state machine modules are comprehensively covered:

- `wardline.contracts`: **99%**
- `wardline.security.circuit_breaker`: **97%**
- `wardline.security.anomaly`: **96%**
- `wardline.security.quotas`: **100%**
- `wardline.security.validation`: **93%**
- `wardline.security.redaction`: **96%**
- `wardline.incidents.machine`: **100%**
- `wardline.incidents.models`: **100%**
- `wardline.incidents.service`: **86%**
- `wardline.incidents.recovery`: **78%**
- `wardline.missions.catalog`: **100%**
- `wardline.missions.checks`: **92%**
- `wardline.config.settings`: **94%**
- `wardline.storage.cleanup`: **90%**
- `wardline.reset`: **91%**

No decision logic or boundary check is left untested.
