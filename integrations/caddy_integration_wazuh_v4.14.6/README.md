# Caddy-Wazuh Integration

## Table of Contents

* [Introduction](#introduction)
* [Prerequisites](#prerequisites)
* [Installation and Configuration](#installation-and-configuration)
    * [Installing Caddy](#installing-caddy)
    * [Initial Caddy Configuration](#initial-caddy-configuration)
    * [Installing Wazuh (if applicable)](#installing-wazuh-if-applicable)
    * [Initial Wazuh Configuration (if applicable)](#initial-wazuh-configuration-if-applicable)
    * [Using the Integration Files](#using-the-integration-files)
* [Integration Steps](#integration-steps)
* [Integration Testing](#integration-testing)
* [Sources](#sources)

---

### Introduction

Caddy (caddyserver.com) is a modern open source web server with automatic HTTPS. It writes structured JSON access logs by default with no extra configuration needed, and there was no coverage for it in the Wazuh ruleset. This integration adds a decoder and a set of detection rules that parse those logs and catch common web attacks and recon activity, things like path traversal, SQL injection, XSS, Log4Shell, credential file access, and dangerous file uploads.

---

### Prerequisites

* Wazuh manager 4.x, developed and tested against 4.14.5
* Caddy web server configured to write JSON access logs
* Wazuh agent installed on the host running Caddy, or the logs forwarded to a location the manager can read

---

### Installation and Configuration

#### Installing Caddy

Follow the official installation guide at https://caddyserver.com/docs/install for your platform.

#### Initial Caddy Configuration

Caddy needs to be told to write JSON access logs. Add this to your Caddyfile:

```
{
    log {
        format json
    }
}
```

A sample log line looks like this:

```json
{"level":"info","ts":1700000000.0,"logger":"http.log.access","msg":"handled request","request":{"remote_ip":"10.0.0.1","remote_port":"12345","proto":"HTTP/1.1","method":"GET","host":"example.com","uri":"/","headers":{"User-Agent":["Mozilla/5.0"]}},"status":200,"size":1024,"duration":0.002}
```

#### Installing Wazuh (if applicable)

A standard Wazuh 4.x installation is assumed. See the official installation guide at https://documentation.wazuh.com/current/installation-guide/index.html.

#### Initial Wazuh Configuration (if applicable)

No special manager configuration is needed beyond placing the decoder and rule files described below and pointing the agent at the Caddy log file.

#### Using the Integration Files

Copy the decoder and rules file into place on the Wazuh manager:

```bash
cp ruleset/decoders/caddy_decoders.xml /var/ossec/etc/decoders/caddy_decoders.xml
cp ruleset/rules/caddy_rules.xml /var/ossec/etc/rules/caddy_rules.xml
chown wazuh:wazuh /var/ossec/etc/decoders/caddy_decoders.xml /var/ossec/etc/rules/caddy_rules.xml
chmod 640 /var/ossec/etc/decoders/caddy_decoders.xml /var/ossec/etc/rules/caddy_rules.xml
```

Then add a localfile block to the agent's ossec.conf so it reads the Caddy log:

```xml
<localfile>
    <log_format>json</log_format>
    <location>/var/log/caddy/access.log</location>
</localfile>
```

Restart Wazuh for the changes to take effect:

```bash
/var/ossec/bin/wazuh-control restart
```

---

### Integration Steps

Once Caddy is writing JSON logs and the agent is configured to read them, every request Caddy handles gets forwarded to the Wazuh manager as a log event. The decoder recognizes the `http.log.access` logger field and extracts the request fields, remote IP, method, URI, user agent, and status. The rules then check those fields against known attack and recon patterns and raise an alert when one matches.

A request like `GET /search?q=1 UNION SELECT username,password FROM users` gets caught by the SQL injection rule (996004), and a request for `/.env` gets caught by the sensitive path probe rule (996005). `sample_logs.txt` in this folder has more examples covering most of the rules.

---

### Integration Testing

This was tested using a Wazuh manager running in Docker (`wazuh/wazuh-manager:4.14.5`) and the `wazuh-logtest` tool.

Load the rules into the container, restart, then feed the sample log lines through logtest:

```bash
docker exec wazuh-test bash -c "
  cp ruleset/rules/caddy_rules.xml /var/ossec/etc/rules/caddy_rules.xml &&
  cp ruleset/decoders/caddy_decoders.xml /var/ossec/etc/decoders/caddy_decoders.xml &&
  chown wazuh:wazuh /var/ossec/etc/rules/caddy_rules.xml /var/ossec/etc/decoders/caddy_decoders.xml &&
  /var/ossec/bin/wazuh-control restart
"
docker exec -i wazuh-test /var/ossec/bin/wazuh-logtest < sample_logs.txt
```

A real logtest hit for the SQL injection rule, taken directly from a test run, looks like this:

```
**Phase 3: Completed filtering (rules).
	id: '996004'
	level: '10'
	description: 'Caddy: SQL injection attempt from 10.0.0.17'
	groups: '['caddy', 'web', 'web', 'attack', 'sql_injection']'
	firedtimes: '1'
	mail: 'False'
	mitre.id: '['T1190']'
	mitre.tactic: '['Initial Access']'
	mitre.technique: '['Exploit Public-Facing Application']'
**Alert to be generated.
```

I also wrote a full test file, `caddy.ini`, for the Wazuh core ruleset testing tool (`runtests.py`), covering 26 test cases across every non frequency based rule, all passing:

```
|          File           |  Passed  |  Failed  |  Status  |
|./caddy.ini              |    26    |    0     |    ✅     |
```

Rules 996018, 996019, and 996022 are frequency based, they need multiple matching events within a time window to fire, so they were left out of the automated test file and need live traffic or a manual multi event test to trigger.

---

### Sources

* Caddy JSON access log format, https://caddyserver.com/docs/logging
* MITRE ATT&CK, https://attack.mitre.org/

## Provenance and Maintenance

* Original source, written from scratch against Caddy's documented JSON access log format, no third party ruleset was adapted or copied.
* Adapted by, Anmol Vats (GitHub: NucleiAv)
* Tested versions, Wazuh manager 4.14.5, current Caddy JSON access log format as documented at caddyserver.com/docs/logging
* Maintainer, Anmol Vats (GitHub: NucleiAv)
* Support boundary, community maintained, provided as is
