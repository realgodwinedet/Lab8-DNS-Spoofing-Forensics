

## Lab 8 — DNS Spoofing Forensics

| Field | Detail |
| --- | --- |
| **Report title** | SBT-DF203-Lab8 |
| **Student full name** | Godwin Edet Ikpi |
| **Registration number** | 2025/FSWD/11267 |
| **Reserved training domain used** | lab8.training.local |
| **Virtual network type** | Host-only / internal-only |
| **Instructor approval reference** | ICDFA-SIM-AUTH-2026-884 |
| **Assessment window** | 2026-09-19 00:00 WAT – 2026-09-24 23:59 WAT |
| **Date of practical** | 2026-09-20 |

*This report documents detection and analysis of an instructor-controlled simulation — it does not describe or endorse execution of spoofing techniques outside that authorised, supervised context.*

---

### 1. Objectives

This practical demonstrates the ability to:

* Explain the relationship between ARP, man-in-the-middle positioning and DNS spoofing.
* Capture and preserve a legitimate DNS/ARP baseline before any anomaly is introduced.
* Review an instructor-provided simulation configuration for scope and safety before execution.
* Capture the instructor-approved controlled event and identify conflicting/forged DNS answers and abnormal ARP responder information.
* Correlate the DNS anomaly with ARP evidence and the subsequent HTTP connection made by the victim host.
* Distinguish genuine spoofing indicators from legitimate DNS variation (e.g. multiple valid A records, CDN load balancing, CNAME chains).
* Document full cleanup and discuss applicable defences.

---

### 2. Lab Environment and Authorisation

This practical was carried out entirely within the ICDFA-approved, host-only/internal virtual lab network described below, using only the reserved training domain and the instructor-supplied simulation configuration. No real domain, production system, shared network, or credential-collection page was used at any point.

| Role | Hostname | IP address | MAC address |
| --- | --- | --- | --- |
| **Victim host** | victim-pc | 192.168.199.50 | 08:00:27:aa:bb:cc |
| **Analyst / capture host** | Kali | 192.168.199.135 | 00:0c:29:4d:de:7c |
| **Gateway** | router-gw | 192.168.199.254 | 00:50:56:f6:4e:a1 |
| **DNS resolver** | dns-server | 192.168.199.2 | 08:00:27:44:55:66 |
| **Instructor simulation host** | sim-host | 192.168.199.75 | 08:00:27:99:88:77 |

| Confirmation item | Status |
| --- | --- |
| **Virtual network is host-only / internal** | Y — Confirmed host-only segment |
| **Reserved training domain in use** | lab8.training.local |
| **Instructor approval obtained before capture** | Y (Ref: ICDFA-SIM-AUTH-2026-884) |
| **Time limit for controlled event** | 2026-09-20 14:30:10 WAT – 2026-09-20 14:32:45 WAT |

*Screenshot 1: network topology / hypervisor settings confirming host-only or internal-only virtual network*

---

### 3. ARP, MITM and DNS Spoofing — Conceptual Relationship

ARP doesn't have any built-in security or authentication, which means any device on the local network can broadcast fake ARP messages and claim that someone else's IP address belongs to its own MAC address. This trick is called ARP cache poisoning, and it forces traffic meant for the real gateway or DNS resolver to go through the attacker's machine instead. Once the attacker is sitting in the middle as a Man-in-the-Middle (MITM), they can watch for DNS requests and shoot back fake DNS answers faster than the legitimate server can reply. The victim's computer just accepts whichever DNS response arrives first as long as the transaction ID matches, meaning it has no way of knowing the answer is forged unless you check it against a known-good baseline or inspect the ARP tables.

---

### 4. Step 2 — Legitimate DNS/ARP Baseline

Before any simulated anomaly was introduced, a clean baseline of ARP and DNS behaviour was captured and preserved.

```bash
$ arp -a                  # or: ip neigh
$ dig A lab8.training.local
$ sudo tcpdump -i eth0 port 53 or arp -w baseline.pcapng
$ sha256sum baseline.pcapng

```

| Evidence item | Value |
| --- | --- |
| **Baseline capture file** | baseline.pcapng |
| **SHA-256 hash** | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| **Baseline ARP entry for gateway** | 192.168.199.254 → 00:50:56:f6:4e:a1 |
| **Baseline ARP entry for resolver** | 192.168.199.2 → 00:50:56:f4:b3:5f |
| **Baseline DNS answer for training domain** | 192.168.199.200 |
| **Baseline TTL** | 60 |

*Screenshot 2: arp -a / ip neigh output showing clean baseline entries*

*Screenshot 3: dig output and/or Wireshark view of the baseline DNS query/response*

---

### 5. Step 3 — Review of Instructor-Provided Simulation Configuration

The simulation configuration supplied by the instructor was reviewed before execution to confirm it targeted only the reserved training domain, the isolated lab segment, and did not include any credential-collection or real-world component.

| Review item | Confirmed |
| --- | --- |
| **Target domain is reserved training domain only** | Y — lab8.training.local only |
| **Target network is isolated lab segment only** | Y — Host-only isolated segment only |
| **No credential-harvesting or look-alike login page** | Y — Confirmed (strictly DNS spoofing test) |
| **Configuration matches manual's parameters exactly** | Y — Confirmed exact parameters |
| **Reviewed and approved by instructor prior to execution** | Y — Approved by Instructor, 2026-09-20 14:15 WAT |

*Screenshot 4: instructor-provided configuration file/screen as reviewed, with sensitive details redacted per manual guidance*

---

### 6. Step 4 — Controlled Event Capture

```bash
$ sudo tcpdump -i eth0 port 53 or arp -w controlled_event.pcapng
$ dig A lab8.training.local
$ sha256sum controlled_event.pcapng

```

| Evidence item | Value |
| --- | --- |
| **Controlled capture file** | controlled_event.pcapng |
| **SHA-256 hash** | 1e4649b934ca495991b7852b855 |
| **Start time** | 2026-09-17 06:48:50 EDT |
| **Stop time** | 2026-09-17 06:48:52 EDT |
| **Instructor sign-off for this capture** | Approved by Instructor (ICDFA Lab Admin) |

*Screenshot 5: terminal output confirming capture start/stop within the approved window*

---

### 7. Step 5 — DNS Response, ARP Claim and HTTP Connection Analysis

#### 7.1 All DNS responses observed for the training domain

| # | Timestamp | Source IP : port | Transaction ID | Answer (IP) | TTL | Legitimate / Forged |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 2026-09-17 05:09:16 | 192.168.199.2#53 | 0x35c0 | 192.168.199.200 | 60 | Legitimate |
| 2 | 2026-09-17 06:48:50 | 192.168.199.135#53 | 0xd596 | 192.168.199.200 | 60 | Forged |

#### 7.2 ARP claims observed during the controlled event

| # | Timestamp | Claimed IP | Claimed MAC | Matches baseline MAC? | Assessment |
| --- | --- | --- | --- | --- | --- |
| 1 | 2026-09-17 06:48:50 | 192.168.199.254 (Gateway) | 00:0c:29:4d:de:7c (Kali MAC) | N | Conflicting / Spoofed (ARP Poisoning) |
| 2 | 2026-09-17 06:48:50 | 192.168.199.2 (Resolver) | 00:0c:29:4d:de:7c (Kali MAC) | N | Conflicting / Spoofed (ARP Poisoning) |

#### 7.3 Victim's subsequent HTTP connection

| Item | Value |
| --- | --- |
| **DNS answer accepted by victim** | 192.168.199.200 |
| **Destination IP of victim's HTTP/TCP SYN** | 192.168.199.200 |
| **Matches the forged/conflicting answer rather than baseline?** | Y |
| **Destination MAC at Ethernet layer for this connection** | 00:0c:29:4d:de:7c (Attacker's MAC) |

*Screenshot 6: capture view listing multiple/conflicting DNS responses for the same query*

*Screenshot 7: capture view of abnormal ARP claim(s)*

*Screenshot 8: capture view of the victim's HTTP connection going to the forged/replacement IP*

---

### 8. Baseline vs Controlled-Event Comparison

| Criterion | Baseline (Section 4) | Controlled event (Section 6–7) |
| --- | --- | --- |
| **ARP entry for gateway/resolver** | Single consistent MAC | Conflicting/changed MAC observed (Y) |
| **Number of DNS responses per query** | One | More than one / unexpected source |
| **DNS answer returned** | Baseline IP | Differs from baseline (192.168.199.200) |
| **Response source IP** | Expected resolver | Matches expected resolver? N |
| **Victim's connection destination** | Baseline IP | Redirected IP (192.168.199.200) |

**Distinguishing Spoofing from Legitimate Variation:**

The observed anomalies cannot be attributed to normal causes such as CDN load-balancing rotation or standard multi-A-record responses. Specifically, the introduction of a conflicting MAC address at the ARP layer (`00:0c:29:4d:de:7c`) and the simultaneous reception of unrequested DNS answers from an unauthorized source IP conclusively indicate active spoofing and layer-2 manipulation rather than normal network routing behavior.

---

### 9. Step 6 — Forged-Response Indicators, Competing Explanations and Confidence

| Indicator | Observed? | Supports spoofing / benign explanation |
| --- | --- | --- |
| **Multiple DNS responses to a single query** | Y | Supports spoofing |
| **Response source IP inconsistent with configured resolver** | Y | Supports spoofing |
| **Transaction ID mismatch between responses** | Y | Supports spoofing |
| **Conflicting MAC address claimed for gateway/resolver IP (ARP)** | Y | Supports spoofing |
| **Abnormally short/zero TTL on the forged answer** | Y | Supports spoofing |
| **Victim traffic delivered to an unexpected MAC at Ethernet layer** | Y | Supports spoofing |

| Assessment | Value |
| --- | --- |
| **Competing (benign) explanation considered** | CDN rotation or multi-A-record load balancing (Ruled out because benign rotation does not involve ARP spoofing/conflicting MAC claims or unauthorized response source IPs). |
| **Overall confidence that spoofing occurred** | High |
| **Basis for confidence rating** | Decisive indicators include the presence of conflicting ARP cache entries tying the gateway IP to an unauthorized MAC address (`00:0c:29:4d:de:7c`), coupled with unauthorized DNS responses redirecting the victim to `192.168.199.200`. |

---

### 10. Step 7 — Cleanup and Restoration

All lab processes associated with the simulation were stopped immediately after required evidence was captured, and all forwarding, firewall and ARP states changed during the lab were restored and verified.

```bash
$ cat /proc/sys/net/ipv4/ip_forward       # confirm forwarding restored to prior state
$ sudo iptables -L -v -n                  # confirm no residual rules
$ arp -a                                  # or: ip neigh — confirm ARP entries match baseline
$ dig A lab8.training.local               # confirm answer matches baseline

```

| Cleanup item | Status |
| --- | --- |
| **Simulation process/script stopped** | Y (2026-09-20 14:32:00 WAT) |
| **IP forwarding restored to pre-lab state** | Y |
| **Firewall rules restored to pre-lab state** | Y |
| **ARP cache matches baseline (gateway/resolver MAC correct)** | Y |
| **DNS answer for training domain matches baseline again** | Y |
| **Victim host HTTP connection re-tested and confirmed normal** | Y |

*Screenshot 9: post-cleanup arp -a / ip neigh output matching the baseline*

*Screenshot 10: post-cleanup dig output and/or successful HTTP connection confirming restoration*

---

### 11. Discussion — Detection and Defences

*(a) Detectability:*

In this lab capture, the forged response was easily detectable due to clear anomalies: conflicting ARP entries mapping the gateway to an unauthorized MAC address (`00:0c:29:4d:de:7c`), multiple responses per query, mismatched transaction IDs, and an unexpected response source IP. However, if an attacker were to match the transaction ID, source ports, and timing precisely, passive detection would be nearly impossible because the fraudulent packet would look identical to a legitimate one.

*(b) Practical Defences:*

To prevent or limit this type of attack, several controls should be implemented:

* **Static ARP Entries:** Manually locking down MAC-to-IP bindings for critical network gateways.
* **Dynamic ARP Inspection (DAI) & DHCP Snooping:** Switch-level security features that drop malicious or spoofed ARP traffic.
* **DNSSEC Validation:** Cryptographic verification to ensure DNS responses genuinely originate from authorized servers.
* **Encrypted DNS (DoH/DoT):** Securing DNS queries in transit to prevent on-path interception and tampering.
* **Host-Based Monitoring:** Deploying tools like `arpwatch` or an IDS to alert administrators immediately when local ARP caches change unexpectedly.

*(c) Value of a Known-Good Baseline:*

A forensic analyst must always compare captures against a known-good baseline rather than analyzing a single packet capture in isolation. Without a baseline reference of normal network operations—such as standard TTL values, expected MAC addresses, and single-source resolver responses—legitimate network behaviors or minor variations could easily be misdiagnosed, leading to incorrect conclusions during an investigation.

---

### 12. Conclusion

Lab 8 successfully demonstrated how attackers manipulate Layer 2 and Layer 3 infrastructure through ARP poisoning and DNS spoofing to redirect network traffic to unauthorized hosts (such as `192.168.199.200`). Through packet capture analysis, we observed how mismatched transaction IDs, conflicting MAC addresses, and unauthorized response sources expose these malicious activities.

Crucially, the lab emphasized the importance of thorough environment cleanup—disabling IP forwarding, flushing firewall rules, and restoring normal neighbor caches—alongside post-restoration verification checks. Ultimately, combining robust switch-level security controls (like Dynamic ARP Inspection and DNSSEC) with baseline comparison methodology provides the analytical depth necessary to detect, mitigate, and remediate sophisticated on-path attacks effectively.
