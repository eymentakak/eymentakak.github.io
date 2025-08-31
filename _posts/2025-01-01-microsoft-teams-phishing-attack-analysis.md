---
title: "Microsoft Teams Phishing: IT Helpdesk Impersonation Attacks and Detection with KQL"
date: 2025-08-31
categories:
  - Security Operations
  - Threat Hunting
tags:
  - Microsoft Teams
  - Phishing
  - KQL
  - Microsoft Sentinel
  - Social Engineering
  - Incident Response
header:
  teaser: /assets/images/teams-phishing-thumb.jpg
  overlay_color: "#c0392b"
  overlay_filter: "0.7"
excerpt: "Analysis of sophisticated Microsoft Teams phishing campaign where attackers impersonate IT helpdesk personnel to gain screen sharing and remote access. Includes KQL queries for detection and threat hunting."
toc: true
toc_label: "Contents"
toc_sticky: true
---

A sophisticated phishing campaign has emerged targeting Microsoft Teams users through IT helpdesk impersonation attacks. This analysis provides technical details, threat indicators, and practical KQL queries for detection and response.

## Attack Overview

Threat actors are exploiting Microsoft Teams' default external communication settings to impersonate IT helpdesk personnel, bypassing traditional email security measures to gain unauthorized access to victim systems.

### Key Attack Vectors

**Primary Method: One-on-One Chat Phishing**
- Attackers use compromised Teams accounts or create malicious Entra ID tenants
- Utilize .onmicrosoft.com domains (Microsoft's default fallback domains)
- Conduct reconnaissance through Teams' user search functionality

**Advanced Technique: Voice Call Phishing (Vishing)**
- Voice calls from external Teams users generate **no security warnings**
- Establishes trust through direct voice communication
- Requests screen sharing permissions once trust is established
- Potentially gains remote control access if organization settings permit

## Technical Implementation

### Attack Chain Analysis

1. **Reconnaissance Phase**
   - Teams user search functionality verification
   - Target email address confirmation
   - Message delivery capability testing

2. **Initial Contact**
   - Direct communication initiation
   - Microsoft's security warnings may appear for text-based communication
   - Warning bypass through voice call initiation

3. **Social Engineering**
   - IT helpdesk impersonation
   - Trust establishment through voice communication
   - Authority exploitation using legitimate platform features

4. **Privilege Escalation**
   - Screen sharing request and approval
   - Remote control capabilities (if enabled)
   - Full workstation access potential

## Threat Intelligence Indicators

### Microsoft 365 Audit Log Artifacts

**Primary Detection Events:**

- **ChatCreated** - New "OneOnOne" chat establishment
- **MessageSent** - Communication metadata logging
- **UserAccepted** - External sender acceptance events
- **TeamsImpersonationDetected** - Brand impersonation detection

### Critical Metadata Fields

- Chat Thread IDs
- Sender display names and email addresses
- Organization IDs for both parties
- Sender IP addresses
- Embedded URL information
- Foreign tenant user indicators

## KQL Detection Queries

### 1. External Teams Chat Creation Detection

```kql
// Detect new external Teams chats with foreign tenant users
CloudAppEvents
| where Timestamp >= ago(7d)
| where Application == "Microsoft Teams"
| where ActionType == "ChatCreated"
| where RawEventData has "OneOnOne"
| where RawEventData has "has_foreign_tenant_users"
| extend ChatThreadId = tostring(RawEventData.ChatThreadId)
| extend ParticipantInfo = tostring(RawEventData.ParticipantInfo)
| extend CommunicationType = tostring(RawEventData.CommunicationType)
| where CommunicationType == "OneOnOne"
| where ParticipantInfo contains "true" // has_foreign_tenant_users = true
| project Timestamp, AccountDisplayName, AccountObjectId, ChatThreadId, ParticipantInfo, IPAddress
| sort by Timestamp desc
```

### 2. Suspicious .onmicrosoft.com Domain Communications

```kql
// Hunt for communications from suspicious .onmicrosoft.com domains
CloudAppEvents
| where Timestamp >= ago(30d)
| where Application == "Microsoft Teams"
| where ActionType in ("ChatCreated", "MessageSent")
| extend SenderEmail = tostring(RawEventData.SenderEmail)
| extend SenderDomain = tostring(split(SenderEmail, "@")[1])
| where SenderDomain endswith ".onmicrosoft.com"
| where SenderDomain !has_any ("your-tenant-name") // Replace with your legitimate tenant
| extend DisplayName = tostring(RawEventData.SenderDisplayName)
| summarize 
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    EventCount = count(),
    UniqueRecipients = dcount(AccountObjectId),
    SampleDisplayNames = make_set(DisplayName, 5)
    by SenderEmail, SenderDomain, IPAddress
| where EventCount > 1 or UniqueRecipients > 1
| sort by UniqueRecipients desc, EventCount desc
```

### 3. IT Helpdesk Impersonation Pattern Detection

```kql
// Detect potential IT helpdesk impersonation based on keywords
let SuspiciousKeywords = dynamic([
    "IT Support", "Help Desk", "Technical Support", "System Administrator",
    "IT Department", "Password Reset", "Account Verification", "Security Update",
    "Urgent", "Action Required", "Verify Account", "Click Here"
]);
CloudAppEvents
| where Timestamp >= ago(7d)
| where Application == "Microsoft Teams"
| where ActionType in ("ChatCreated", "MessageSent")
| extend SenderDisplayName = tostring(RawEventData.SenderDisplayName)
| extend MessageText = tostring(RawEventData.MessageText)
| where SenderDisplayName has_any (SuspiciousKeywords) 
    or MessageText has_any (SuspiciousKeywords)
| extend SenderEmail = tostring(RawEventData.SenderEmail)
| extend RecipientEmail = tostring(RawEventData.RecipientEmail)
| project Timestamp, SenderDisplayName, SenderEmail, RecipientEmail, 
          ActionType, MessageText, IPAddress
| sort by Timestamp desc
```

### 4. Screen Sharing and Remote Control Activity Monitoring

```kql
// Monitor for screen sharing requests and remote control activities
CloudAppEvents
| where Timestamp >= ago(7d)
| where Application == "Microsoft Teams"
| where ActionType in ("ScreenSharingStarted", "RemoteControlRequested", "RemoteControlGranted")
| extend ParticipantInfo = tostring(RawEventData.ParticipantInfo)
| extend ExternalUser = RawEventData contains "external" or RawEventData contains "guest"
| extend MeetingId = tostring(RawEventData.MeetingId)
| project Timestamp, AccountDisplayName, ActionType, MeetingId, 
          ParticipantInfo, ExternalUser, IPAddress
| sort by Timestamp desc
```

### 5. Teams Impersonation Detection Events

```kql
// Leverage Microsoft's built-in impersonation detection
CloudAppEvents
| where Timestamp >= ago(30d)
| where Application == "Microsoft Teams"
| where ActionType == "TeamsImpersonationDetected"
| extend ImpersonationDetails = tostring(RawEventData.ImpersonationDetails)
| extend SuspectedSender = tostring(RawEventData.SuspectedSender)
| extend TargetedUser = tostring(RawEventData.TargetedUser)
| project Timestamp, SuspectedSender, TargetedUser, ImpersonationDetails, IPAddress
| sort by Timestamp desc
```

### 6. Advanced Behavioral Analysis Query

```kql
// Detect unusual external communication patterns
let NormalExternalDomains = dynamic([
    "partner1.com", "vendor1.com" // Add your legitimate external partners
]);
CloudAppEvents
| where Timestamp >= ago(14d)
| where Application == "Microsoft Teams"
| where ActionType in ("ChatCreated", "MessageSent")
| extend SenderEmail = tostring(RawEventData.SenderEmail)
| extend SenderDomain = tostring(split(SenderEmail, "@")[1])
| where isnotempty(SenderDomain)
| where SenderDomain !in (NormalExternalDomains)
| where SenderDomain endswith ".onmicrosoft.com" or not(SenderDomain contains "your-domain.com")
| summarize 
    FirstContact = min(Timestamp),
    LastContact = max(Timestamp),
    ContactCount = count(),
    UniqueTargets = dcount(AccountObjectId),
    TargetUsers = make_set(AccountDisplayName, 10)
    by SenderEmail, SenderDomain
| where ContactCount >= 3 or UniqueTargets >= 2
| extend SuspicionScore = (ContactCount * 2) + (UniqueTargets * 5)
| sort by SuspicionScore desc, UniqueTargets desc
```

## Detection and Response Recommendations

### Immediate Actions

1. **Enable Advanced Audit Logging**
   ```powershell
   # Enable Teams audit logging
   Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true
   ```

2. **Configure External Communication Restrictions**
   - Review and restrict external communication settings
   - Implement domain allowlists for trusted partners
   - Disable external federation if not required

3. **Deploy Custom Detection Rules**
   - Implement KQL queries as custom analytics rules in Microsoft Sentinel
   - Configure appropriate alert thresholds and notification channels

### Long-term Mitigation Strategies

**Technical Controls:**
- Implement Conditional Access policies for Teams
- Enable Multi-Factor Authentication for all users
- Deploy Microsoft Defender for Office 365
- Configure Data Loss Prevention (DLP) policies

**User Education:**
- Conduct phishing awareness training focused on Teams-based attacks
- Establish clear IT helpdesk communication protocols
- Implement verification procedures for remote access requests

**Process Improvements:**
- Develop incident response playbooks for Teams-based attacks
- Establish baseline behavior patterns for external communications
- Implement regular security assessments of Teams configurations

## Threat Hunting Playbook

### Phase 1: Discovery
1. Execute external communication detection queries
2. Identify suspicious .onmicrosoft.com domain communications
3. Review Teams impersonation detection events

### Phase 2: Analysis
1. Correlate chat creation events with message activities
2. Analyze sender behavior patterns and timing
3. Identify potential victim accounts and communication threads

### Phase 3: Containment
1. Block suspicious sender domains and accounts
2. Reset compromised user credentials
3. Review and audit external communication settings

### Phase 4: Recovery
1. Implement enhanced monitoring for affected users
2. Deploy additional security controls based on findings
3. Update security awareness training content

## IOCs and Threat Indicators

**Behavioral Indicators:**
- Unexpected IT support contact via Teams
- External users requesting screen sharing
- Urgent password reset requests
- Authority figure impersonation

**Technical Indicators:**
- .onmicrosoft.com domains not belonging to organization
- OneOnOne chat creation with foreign tenant users
- Screen sharing requests from external participants
- High-frequency external communication attempts

## Conclusion

This Microsoft Teams phishing campaign represents a sophisticated evolution of social engineering attacks, leveraging legitimate platform functionality to bypass traditional security controls. The combination of voice-based communication and screen sharing capabilities creates significant risk exposure for organizations.

Security teams must implement comprehensive monitoring strategies using the provided KQL queries while simultaneously addressing configuration weaknesses in Teams external communication settings. The key to effective defense lies in combining technical detection capabilities with user education and process improvements.

Organizations should immediately review their Teams security configurations and implement the detection queries provided to identify potential compromise attempts. As attackers continue to evolve their tactics, maintaining vigilant monitoring and adaptive security measures will be crucial for protecting against these sophisticated threats.

---

**References:**
- [Cybersecurity News: Hackers Exploit Microsoft Teams](https://cybersecuritynews.com/hackers-exploit-microsoft-teams/)
- [Hunters Security: Microsoft Teams Phishing Analysis](https://www.hunters.security/en/blog/microsoft-teams-phishing-fake-it-helpdesk)
- Microsoft 365 Security Documentation

*This analysis is part of my ongoing security research and Microsoft SC-200 certification journey. For questions or collaboration on threat hunting initiatives, feel free to reach out.*
