# Network Security Threats: A Research Report

**Author:** Nathan Desouza  
**Internship:** CodeAlpha Cybersecurity Internship (Student ID: CA/DF1/274897)  
**Task:** Task 4 — Research Report: Common Network Security Threats

---

## Introduction

The internet was built for connectivity, not security — and that foundational gap is something attackers have been exploiting for decades. As organizations shift more of their infrastructure online and attack surfaces expand (cloud, IoT, remote work), network-level threats aren't just a concern for large enterprises anymore. A misconfigured DNS server at a small startup, an unpatched UDP port on a university network, or an unencrypted public Wi-Fi session at a coffee shop — any of these can become an entry point for a crippling attack. Understanding how these threats actually work, not just what they're called, is the first step toward building defenses that hold up in the real world. This report covers four of the most impactful network security threats: DoS/DDoS attacks, Man-in-the-Middle attacks, IP Spoofing, and DNS Poisoning — along with real incidents, concrete mitigations, and a comparison of how they stack up against each other.

---

## 1. DoS/DDoS Attacks

### How It Works

A **Denial of Service (DoS)** attack floods a target system — a server, network, or application — with more traffic than it can handle, forcing it offline. A **Distributed Denial of Service (DDoS)** scales this up by recruiting hundreds or thousands of compromised machines (a botnet) to launch the flood simultaneously, making the source harder to block and the volume harder to absorb.

There are three main categories:
- **Volumetric attacks** — flood the bandwidth (e.g., UDP floods, ICMP floods)
- **Protocol attacks** — exploit weaknesses in Layer 3/4 protocols (e.g., SYN floods)
- **Application-layer attacks** — target Layer 7 by mimicking legitimate user requests (e.g., HTTP GET floods)

Amplification attacks are a particularly nasty variant — the attacker spoofs the victim's IP address and sends small requests to publicly accessible servers (DNS, NTP, Memcached) that respond with responses orders of magnitude larger, effectively using someone else's infrastructure to do the heavy lifting.

MITRE ATT&CK classifies DDoS under **T1498 (Network Denial of Service)** and **T1499 (Endpoint Denial of Service)**.

### Real-World Example: GitHub, February 2018

<cite index="1-1">On February 28, 2018, GitHub was hit with what was at the time the largest DDoS attack ever recorded, peaking at 1.35 Tbps.</cite> What made it unusual: <cite index="1-1">attackers didn't use a botnet. Instead, they weaponized misconfigured Memcached servers — an open-source distributed caching system — to amplify traffic by over 51,000 times the original request size.</cite> The technique, dubbed "Memcrashed," works by <cite index="1-1">sending a forged request to a vulnerable Memcached server on UDP port 11211 using a spoofed IP address matching the victim. A few bytes sent in triggers tens of thousands of times the data back at the target.</cite>

<cite index="4-1">GitHub called in Akamai Prolexic, which rerouted traffic through scrubbing centers that filtered out malicious data. The attack was mitigated in 8 minutes, with GitHub experiencing intermittent outages but no complete takedown.</cite>

### Impact

- Service disruption affecting millions of developers globally
- Revenue loss and SLA violations for enterprise GitHub customers
- Reputational damage — even brief outages at that scale make headlines
- Demonstrates that even well-resourced companies with DDoS defenses can be caught off guard by novel amplification vectors

### Mitigation Strategies

1. **Rate limiting and traffic scrubbing** — Deploy a CDN or DDoS mitigation service (Cloudflare, Akamai) that can absorb volumetric attacks and filter malicious traffic before it hits origin infrastructure.

2. **Ingress/egress filtering (BCP38)** — Implement network-level filtering to drop packets with spoofed source IPs. This directly cuts off amplification attacks at the source. CISA recommends BCP38 compliance as a baseline for any network operator.

3. **Disable unused UDP services** — <cite index="1-1">Specifically for Memcached, administrators should disable UDP support if not in use, or firewall off port 11211 from public access.</cite> More broadly, close any publicly exposed UDP-based services that aren't strictly necessary.

---

## 2. Man-in-the-Middle (MITM) Attacks

### How It Works

A **Man-in-the-Middle (MITM)** attack is exactly what it sounds like — an attacker positions themselves between two communicating parties and intercepts, reads, or modifies the traffic without either side realizing. The attacker becomes a transparent relay: they receive traffic meant for the server, can read or alter it, then forward it on as if nothing happened.

Common techniques include:
- **ARP Spoofing** — the attacker sends fake ARP replies on a LAN, associating their MAC address with a legitimate IP so traffic is rerouted through them
- **SSL Stripping** — downgrading an HTTPS connection to HTTP so traffic is transmitted in plaintext
- **Rogue Access Points** — setting up a fake Wi-Fi hotspot that users connect to, giving the attacker full visibility of their traffic
- **Certificate Spoofing** — using a fraudulent or compromised SSL certificate to impersonate a legitimate server

MITRE ATT&CK maps this to **T1557 (Adversary-in-the-Middle)**.

### Real-World Example: Lenovo Superfish, 2015

<cite index="8-1">In early 2015, it came to light that Lenovo had been shipping consumer laptops pre-installed with software called Superfish, which performed man-in-the-middle attacks against users' HTTPS browsing in order to inject advertising into secure pages.</cite>

The problem went beyond intrusive ads. <cite index="8-1">Superfish used a single root certificate to perform all its MITM operations — and researchers discovered 44,000 Superfish MITM certificates all signed by the same root cert.</cite> Once that root cert's private key was cracked and published (which happened quickly), <cite index="15-1">attackers on the same network as a Lenovo user — say, at a coffee shop — could read all encrypted communications, steal passwords, and spoof legitimate websites with phishing pages.</cite>

<cite index="13-1">Lenovo admitted to the preinstallation, calling it a "Man-in-the-Middle Attack" with a severity rating of High in their own security advisory (LEN-2015-010).</cite>

### Impact

- Millions of Lenovo consumer laptops shipped with broken HTTPS security
- Users' banking, email, and login credentials exposed to anyone on the same network
- Massive erosion of trust in Lenovo's consumer products
- Highlighted the risk of supply-chain-level security compromises (threats don't always come from outside)

### Mitigation Strategies

1. **Enforce HTTPS + HSTS** — Use HTTP Strict Transport Security (HSTS) to prevent SSL stripping. Ensure certificates are issued by trusted, audited Certificate Authorities, and implement certificate pinning for sensitive applications.

2. **Network monitoring and anomaly detection** — Deploy IDS/IPS solutions to detect suspicious ARP patterns (ARP inspection on managed switches), unexpected certificate changes, or unusual traffic rerouting. Tools like Wireshark can help identify MITM attempts during forensic analysis.

3. **Mutual TLS (mTLS)** — For internal service-to-service communication, implement mutual authentication so both parties verify each other's certificates. This eliminates the possibility of a rogue relay silently forwarding traffic.

---

## 3. IP Spoofing

### How It Works

Every IP packet has a source address field in its header. **IP Spoofing** is the act of forging that field — putting a fake IP address in the "from" field to impersonate another machine, hide the attacker's real location, or trick systems that rely on IP-based trust.

By itself, IP spoofing doesn't give the attacker visibility into the response traffic (since replies go to the forged address, not the attacker). That's why it's rarely used in isolation — it's a force multiplier for other attacks:
- **DDoS amplification** — spoof the victim's IP so reflected traffic slams them (as in the GitHub 2018 attack above)
- **Session hijacking** — forge packets to inject commands into an established TCP session
- **Firewall bypass** — impersonate a trusted IP to get past IP-based access control lists

The attack works at the IP layer (Layer 3) — the attacker constructs raw packets with a manually set source IP, often using tools like Scapy or Hping3.

MITRE ATT&CK covers this under **T1599 (Network Boundary Bridging)** and it's a core enabler for **T1498 (Network Denial of Service)**.

### Real-World Example: Memcrashed / GitHub 2018 (IP Spoofing Component)

<cite index="29-1">The 2018 GitHub DDoS attack was a direct application of IP spoofing at scale — attackers forged GitHub's IP address and sent queries to publicly exposed Memcached servers, which then amplified the traffic and directed it back at GitHub.</cite> The spoofed source IP was the linchpin that made the amplification work — without it, the reflected traffic would have gone back to the attacker, not the victim.

Beyond DDoS: <cite index="34-1">research by the Center for Applied Internet Data Analysis (CAIDA) found that over 2020, approximately 187,000 spoofing-based attacks were recorded every day, totaling 126 million for the year, with 37.3 million unique IP addresses targeted.</cite>

### Impact

- Enables large-scale DDoS attacks that are nearly impossible to trace back to the real attacker
- Bypasses firewall rules and ACLs that rely on IP-based trust relationships
- Makes forensic attribution extremely difficult — logs show a victim IP, not the real attacker
- Can be used to frame innocent parties (their IP appears in abuse logs for attacks they didn't launch)

### Mitigation Strategies

1. **Implement BCP38 (ingress filtering)** — Network operators should drop packets arriving on an interface with a source IP that couldn't have legitimately come from that direction. This is the single most effective countermeasure at the infrastructure level and is recommended by both CISA and NIST as a baseline.

2. **Unicast Reverse Path Forwarding (uRPF)** — Enable uRPF on routers so that incoming packets are verified against the routing table. If the source IP doesn't have a valid return route through the receiving interface, the packet is dropped.

3. **Access Control Lists (ACLs) and firewall rules** — Block packets claiming to originate from private/reserved address ranges (RFC 1918 addresses, loopback, link-local) if arriving from external interfaces. These are called "bogon" addresses and should never appear as source IPs from the public internet.

---

## 4. DNS Poisoning / Spoofing (Bonus Threat)

### How It Works

The DNS is basically the internet's phone book — it translates human-readable domain names (google.com) into IP addresses machines can route to. **DNS Cache Poisoning** attacks corrupt that translation by injecting fake DNS records into a resolver's cache, so when users look up a legitimate domain, they get redirected to a malicious IP instead.

The attack flow:
1. Attacker sends a flood of forged DNS responses to a recursive resolver
2. Each response contains a fake "answer" mapping a real domain to the attacker's IP
3. If the forged response arrives before the legitimate one and the transaction ID matches, the resolver caches the fake record
4. Every user querying that resolver now gets the wrong IP — possibly for minutes, hours, or until the TTL expires

The difficulty historically was guessing the 16-bit transaction ID. The Kaminsky attack solved this by querying random subdomains — generating fresh attack windows for each query instead of waiting for a cached record to expire.

MITRE ATT&CK maps this to **T1584.002 (Compromise Infrastructure: DNS Server)** and **T1071.004 (Application Layer Protocol: DNS)**.

### Real-World Example: The Kaminsky Bug, 2008

<cite index="26-1">Discovered by security researcher Dan Kaminsky in 2008 (CVE-2008-1447), the Kaminsky attack fundamentally changed how seriously the security community treated DNS vulnerabilities.</cite>

<cite index="26-1">Kaminsky's insight was to target random subdomains rather than waiting for a cached record to expire. By querying aaa.example.com, then bbb.example.com, then ccc.example.com — each generating a fresh cache miss — an attacker could flood each with thousands of forged responses containing false authority records for the parent domain. This meant virtually any DNS resolver could be poisoned within seconds or minutes.</cite>

<cite index="26-1">The response was coordinated across all major DNS resolver software vendors simultaneously — an unusual level of industry cooperation — and patched via source port randomization.</cite>

A more recent example: in 2018, the DNS records for MyEtherWallet were poisoned via a BGP hijack, redirecting users to a phishing site that drained cryptocurrency wallets before the attack was detected and mitigated.

### Impact

- Users redirected to phishing sites that look identical to legitimate ones
- Credential theft, financial fraud, malware delivery
- Attacks can affect thousands of users simultaneously through a single poisoned resolver
- Difficult to detect because the user's browser shows the correct URL — the misdirection happens at the DNS layer

### Mitigation Strategies

1. **Deploy DNSSEC** — DNS Security Extensions add cryptographic signatures to DNS records. Resolvers verify these signatures before accepting a response, making it impossible to poison a record without the private key of the authoritative zone. NIST SP 800-81 Rev 2 provides deployment guidance.

2. **Source port randomization** — The post-Kaminsky patch randomized the UDP source port used for DNS queries, increasing the entropy an attacker has to guess from 16 bits (65,536 possibilities) to effectively 32 bits. All modern resolvers should have this enabled by default.

3. **Use encrypted DNS (DoH/DoT)** — DNS over HTTPS (DoH) and DNS over TLS (DoT) encrypt DNS queries in transit, preventing on-path attackers from injecting forged responses. Both CISA and major browsers now support or mandate these protocols in hardened configurations.

---

## Comparison Table

| Attribute | DoS/DDoS | MITM | IP Spoofing | DNS Poisoning |
|-----------|----------|------|-------------|---------------|
| **Attack Vector** | Network flood / amplification | On-path interception (LAN, rogue AP, SSL strip) | Forged IP packet headers | Injected fake DNS responses |
| **Who Is at Risk** | Any internet-facing service or infrastructure | Users on untrusted networks; services without mTLS | Organizations relying on IP-based trust; DDoS victims | Any user relying on unprotected DNS resolvers |
| **Difficulty to Execute** | Low–Medium (tools freely available; botnet required for scale) | Medium (requires network positioning; SSL stripping is harder with HSTS) | Medium (requires raw socket access; easier inside networks) | Medium–High (timing-dependent; Kaminsky made it easier) |
| **Ease of Mitigation** | Medium (CDN/scrubbing helps, but volumetric attacks still challenging) | Medium (HTTPS/HSTS is widely adopted; rogue APs harder to stop) | Medium (BCP38 helps but not universally deployed) | Medium (DNSSEC solves it but adoption is still incomplete) |
| **Primary Goal** | Availability disruption | Confidentiality / Integrity compromise | Anonymity / Amplification enablement | Integrity compromise / Phishing |
| **Detectable?** | Yes (traffic anomalies obvious) | Hard in real-time (passive by nature) | Hard (forged header looks legitimate) | Hard (user sees correct URL) |

---

## Conclusion: 3 Key Takeaways for a Network Administrator

1. **Layered defense is non-negotiable.** No single control stops all four of these threats. A firewall alone won't stop a DDoS. HTTPS alone won't stop DNS poisoning if the resolver is compromised. The only realistic posture is defense-in-depth — combine network filtering (BCP38, uRPF), encrypted protocols (TLS, DoH/DoT), and anomaly detection (IDS/IPS) so that if one layer fails, another catches it.

2. **Default configurations will get you breached.** The GitHub 2018 attack succeeded because Memcached servers were publicly exposed on UDP with no authentication — default behavior. The Kaminsky attack worked because DNS resolvers used predictable transaction IDs — default behavior. Superfish worked because users trusted their manufacturer's root certificate — default behavior. Treat defaults as a starting point, not a security posture.

3. **Attribution is hard; logging isn't optional.** IP spoofing means attacker IPs in logs are often meaningless. DNS poisoning means users are at the wrong server without knowing it. The only way to reconstruct what happened — and defend against the next variant — is comprehensive, centralized logging of DNS queries, traffic flows, certificate changes, and authentication events. Without logs, you're flying blind both during an incident and after.

---

## References

1. **CISA** — *Understanding and Responding to Distributed Denial-of-Service Attacks* (October 2022). https://www.cisa.gov/resources-tools/resources/understanding-and-responding-distributed-denial-service-attacks

2. **NIST SP 800-81 Rev 2** — *Secure Domain Name System (DNS) Deployment Guide*. https://csrc.nist.gov/publications/detail/sp/800-81/2/final

3. **MITRE ATT&CK** — Techniques: T1498 (Network Denial of Service), T1557 (Adversary-in-the-Middle), T1599 (Network Boundary Bridging), T1584.002 (DNS Server Compromise). https://attack.mitre.org/

4. **GitHub Engineering Blog** — *February 28th DDoS Incident Report* (March 1, 2018). https://github.blog/2018-03-01-ddos-incident-report/

5. **US-CERT / CVE-2008-1447** — *Kaminsky DNS Cache Poisoning Vulnerability*. https://www.kb.cert.org/vuls/id/800113

6. **Electronic Frontier Foundation (EFF)** — *Further Evidence of Lenovo Breaking HTTPS Security on Its Laptops* (February 2015). https://www.eff.org/deeplinks/2015/02/further-evidence-lenovo-breaking-https-security-its-laptops

7. **CAIDA** — *Spoofer Project: Measuring and Reducing IP Spoofing on the Internet*. https://www.caida.org/projects/spoofer/

8. **SANS Institute** — *DNS Attacks and Security* (Reading Room). https://www.sans.org/reading-room/

---

*Report prepared for CodeAlpha Cybersecurity Internship — Task 4*
