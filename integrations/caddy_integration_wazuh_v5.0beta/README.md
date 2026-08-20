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

Caddy (caddyserver.com) is a modern open source web server with automatic HTTPS. It writes structured JSON access logs by default with no extra configuration needed, and there was no coverage for it in the Wazuh ruleset. This integration adds a decoder and a set of Sigma format detection rules for Wazuh 5.0, parsing Caddy's JSON access logs into ECS fields and catching common web attacks and recon activity, things like path traversal, SQL injection, XSS, Log4Shell, credential file access, and dangerous file uploads.

A parallel version of this integration for Wazuh 4.x (XML decoder and rules) is available in a separate branch/PR of this repository.

---

### Prerequisites

* Wazuh manager 5.0 beta2 or later, the ruleset format described here is specific to the new engine introduced in 5.0
* Caddy web server configured to write JSON access logs

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

A standard Wazuh 5.0 beta installation is assumed. See the beta documentation at https://documentation.wazuh.com/5.0-beta/getting-started/index.html.

#### Initial Wazuh Configuration (if applicable)

No special manager configuration is needed beyond registering the decoder and rules described below and pointing the agent at the Caddy log file.

#### Using the Integration Files

In 5.0, decoders and rules are authored as YAML assets rather than XML, and rules follow the Sigma rule specification (https://github.com/SigmaHQ/sigma-specification). The easiest way to add this integration is through the dashboard's Security Analytics section, under Normalization and Detection, both have a Create option with a YAML editor.

* `ruleset/decoders/decoder_caddy-access_0.yml`, paste into Normalization, Decoders, Create, YAML Editor. Set its parent integration to a new or existing `caddy` integration.
* `ruleset/rules/*.yml`, each file is one rule, paste into Detection, Rules, Create, YAML Editor, same `caddy` integration.

Once added, content should be promoted from the Draft space through Test and into Custom or Standard depending on your review process, so it is picked up by live detection.

---

### Integration Steps

Once Caddy is writing JSON logs and the agent is forwarding them, every request Caddy handles becomes a log event. The decoder recognizes the `http.log.access` logger field and maps the request into ECS fields (`source.ip`, `url.original`, `http.request.method`, `http.response.status_code`, `user_agent.original`, and so on). The rules then match against those ECS fields and raise an alert when a known attack or recon pattern is found.

A request like `GET /../../../../etc/passwd` gets caught by the path traversal rule, and a request containing `${jndi:ldap://...}` gets caught by the Log4Shell rule.

---

### Integration Testing

This was verified using the Wazuh 5.0 beta2 dashboard's Log test tool (Security Analytics, Log test). Custom content was authored in the Draft space and promoted to the Test space before running it against sample logs, since Draft content alone is not evaluated by Log test.

Running the path traversal sample log (`/../../../../etc/passwd`) through Log test produces a decoded event with all ECS fields populated correctly. The Detection tab reports 25 rules evaluated with 2 matches on that single log line, the path traversal rule (996003) and the suspicious filename rule (996020), both firing correctly against the same request.

The other 23 rules in `ruleset/rules/` were built the same way and follow the same pattern. 19 target `url.original`, 2 target `user_agent.original` (996010, 996028), and 2 target `http.request.method` (996011, 996027), each with a regex modifier. Across all 25 rules, 21 target `url.original` in total.

<img width="1716" height="687" alt="image" src="https://github.com/user-attachments/assets/6d090837-a63e-4877-9330-a871d861e6dd" />
<img width="1917" height="761" alt="image" src="https://github.com/user-attachments/assets/7a51a480-6e39-4b08-8115-ff1a33db66b0" />

Three rules from the original Wazuh 4.x ruleset (repeated auth endpoint hits, repeated sensitive path probes, repeated path traversal attempts) rely on frequency and correlation logic across multiple events rather than a single log line, and are not included here as Sigma rules. That kind of correlation looks like it belongs in the dashboard's Detectors feature instead, which is still to be worked out and would follow in a later update.

---

### Sources

* Caddy JSON access log format, https://caddyserver.com/docs/logging
* Sigma rule specification, https://github.com/SigmaHQ/sigma-specification
* MITRE ATT&CK, https://attack.mitre.org/

## Provenance and Maintenance

* Original source, ported from a Wazuh 4.x XML decoder and ruleset I wrote for the same Caddy log format, adapted to the 5.0 YAML and Sigma format.
* Adapted by, Anmol Vats (GitHub: NucleiAv)
* Tested versions, Wazuh 5.0.0 beta2, current Caddy JSON access log format as documented at caddyserver.com/docs/logging
* Maintainer, Anmol Vats (GitHub: NucleiAv)
* Support boundary, community maintained, provided as is, format may need updates as the 5.0 engine moves past beta
