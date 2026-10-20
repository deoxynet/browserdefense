# BrowserDefense YouTube Demo Script

**Duration:** 5-7 minutes
**Format:** Screen recording with voiceover
**Target Audience:** SOC analysts, security engineers, IT security managers

---

## Pre-Recording Checklist

- [ ] Chrome with BrowserDefense extension installed (demo/test mode)
- [ ] Terminal window with connector service logs visible
- [ ] Splunk (or mock SIEM dashboard) ready to show incoming events
- [ ] Test phishing URL ready (use a safe demo domain)
- [ ] Quiet recording environment
- [ ] Screen resolution: 1920x1080

---

## INTRO (0:00 - 0:45)

### Visual
- BrowserDefense logo animation
- Fade to: analyst at desk, abuse inbox on screen

### Script

> "You're a SOC analyst. It's Tuesday morning, and your abuse inbox has a phishing report. An employee clicked a suspicious link in an email.
>
> You've got the malicious URL. Now what?
>
> Do you open a ticket with IT to update the firewall? Wait three days for a change window? Hope nobody else clicks it in the meantime?
>
> What if you could block that URL across your entire organization in under 30 seconds, and automatically capture forensic evidence whenever someone tries to click it?
>
> That's BrowserDefense. Let me show you how it works."

---

## SECTION 1: The Extension (0:45 - 2:00)

### Visual
- Show Chrome browser with BrowserDefense extension icon in toolbar
- Click to open the popup
- Show the clean, minimal interface

### Script

> "BrowserDefense is a Chrome extension that blocks malicious URLs at the browser level. No VPN required, no heavy agent, works on any managed device.
>
> Here's the extension popup. You can see we're connected and protection is active.
>
> This shows us 847 IOCs are currently in the blocklist. These came from our organization's threat intel feed, signed and verified.
>
> Now let's add the phishing URL from that abuse report."

### Action
1. Open extension popup
2. Highlight the active status indicator
3. Show the IOC count
4. Click "Add IOC" or navigate to the options page

### Visual
- Options page or quick-add interface
- Paste: `https://evil-phishing-site.example.com/login`

### Script

> "I'll paste in the malicious URL we identified: evil-phishing-site.example.com/login.
>
> Click 'Add to blocklist.'
>
> And done. That URL is now blocked across every browser in our organization that has BrowserDefense installed. Took about five seconds.
>
> Behind the scenes, the extension normalized this URL, hashed it with our organization's salt, and added it to the local blocklist. No plaintext IOC ever left the browser."

---

## SECTION 2: Blocking in Action (2:00 - 3:30)

### Visual
- New Chrome tab
- Type the phishing URL in the address bar
- Press Enter

### Script

> "Now let's see what happens when someone tries to visit that URL.
>
> I'll open a new tab and type in the phishing site address."

### Action
- Navigate to `https://evil-phishing-site.example.com/login`
- Block page appears

### Visual
- BrowserDefense block page with:
  - Warning icon
  - "This site has been blocked" message
  - URL that was blocked
  - Timestamp
  - "Report if this is a mistake" link

### Script

> "Immediately, BrowserDefense intercepts the request and shows this block page.
>
> The user sees a clear message: this site has been blocked by your organization's security team.
>
> Notice we show the blocked URL and the timestamp. There's also a link if the user believes this is a mistake, which goes back to the SOC team.
>
> But here's where it gets interesting. BrowserDefense didn't just block the request. It captured forensic evidence."

---

## SECTION 3: Forensics Capture (3:30 - 4:45)

### Visual
- Click extension icon again
- Navigate to "Recent Blocks" or similar section
- Show the captured forensic event

### Script

> "Back in the extension popup, I can see the recent block event.
>
> This shows us:"

### Action
Highlight each item as you mention it:

1. **Blocked URL** - `https://evil-phishing-site.example.com/login`
2. **Timestamp** - `2024-01-15 10:32:47 UTC`
3. **Redirect Chain** - Shows: `email-link.com -> tracker.example.com -> evil-phishing-site.example.com`
4. **Tab Context** - Shows the page they were on when they clicked

### Script

> "The blocked URL, the exact timestamp, and critically, the redirect chain.
>
> See this? The user didn't type in the phishing URL directly. They clicked a link that went through two redirects before landing on the malicious site.
>
> This redirect chain is gold for incident response. You can see the entire attack path, from the initial email link through the tracking domain to the final phishing page.
>
> Now let's see how this data gets to your SIEM."

---

## SECTION 4: Connector and SIEM Integration (4:45 - 6:00)

### Visual
- Switch to terminal window showing connector service
- Show a log entry of incoming encrypted payload
- Show decryption happening
- Show forward to Splunk

### Script

> "BrowserDefense uses a zero-knowledge architecture. The forensic data is encrypted in the browser using your organization's public key before it leaves the endpoint.
>
> Here's our connector service running on-premises. Watch what happens."

### Action
- Refresh or trigger a new block event
- Show the connector logs:
  ```
  [INFO] Received encrypted payload from org-123
  [INFO] Decrypting with RSA-OAEP + AES-GCM
  [INFO] Forwarding to connector: prod-splunk
  [INFO] Event evt-abc123 delivered successfully
  ```

### Script

> "The connector receives the encrypted payload, decrypts it using your organization's private key, which never leaves your environment, and forwards the plaintext event to Splunk.
>
> BrowserDefense's servers never see your forensic data in plaintext. We literally cannot read it."

### Visual
- Switch to Splunk dashboard
- Show the incoming event with all fields

### Script

> "And here it is in Splunk. The full forensic event with all the context your incident responders need.
>
> Blocked URL, redirect chain, user information, device ID, and timestamp. All searchable, all correlatable with your other security data.
>
> You can set up alerts in Splunk to notify the SOC when a block occurs, automatically enrich the event with threat intel, or kick off a SOAR playbook."

### Action
- Show a quick Splunk search: `source="browserdefense" | table timestamp, blocked_url, redirect_chain`
- Show results

---

## SECTION 5: Recap and Call to Action (6:00 - 6:45)

### Visual
- Split screen or montage of:
  - Adding IOC (5 seconds)
  - Block page appearing
  - Forensics in Splunk

### Script

> "Let's recap what we just did:
>
> 1. We identified a phishing URL from an abuse report
> 2. Added it to our blocklist in five seconds
> 3. BrowserDefense immediately protected our entire organization
> 4. When someone tried to visit the URL, they were blocked
> 5. Forensic evidence was automatically captured and encrypted
> 6. The connector decrypted and forwarded the event to our SIEM
>
> No IT tickets. No change windows. No VPN required. No vendor seeing your data.
>
> This is browser-level IOC blocking with zero-knowledge forensics."

### Visual
- BrowserDefense logo
- Website URL: browserdefense.com
- GitHub link

### Script

> "BrowserDefense is open source and available today.
>
> Visit browserdefense.com to get started. The extension is free for up to 1,000 IOCs.
>
> For enterprise features like the connector SDK, unlimited IOCs, and policy-based deployment, check out our team plans.
>
> Questions? Drop them in the comments or open an issue on GitHub.
>
> Thanks for watching. Block fast. Stay safe."

---

## END CARD (6:45 - 7:00)

### Visual
- Subscribe button animation
- Links:
  - browserdefense.com
  - github.com/irdbl/browserdefense
  - @browserdefense on Twitter/X

---

## B-Roll Suggestions

Capture these clips separately for editing flexibility:

1. **Typing the phishing URL** - Close-up of keyboard
2. **Block page appearing** - Multiple takes with different URLs
3. **Splunk dashboard refresh** - Shows event appearing in real-time
4. **Terminal logs scrolling** - Connector processing events
5. **Extension popup states** - Open, hover, different tabs

---

## Technical Notes for Recording

### Extension Demo Mode

Set the extension to demo mode to use safe test URLs:

```javascript
// In extension options or via chrome.storage.local
{ "demoMode": true, "demoUrls": ["evil-phishing-site.example.com"] }
```

### Connector Test Mode

Run the connector with verbose logging:

```bash
BROWSERDEFENSE_LOG_LEVEL=debug browserdefense-connector --config demo-config.yaml
```

### Splunk Test Index

Use a dedicated demo index to avoid cluttering production data:

```yaml
connectors:
  - name: "demo-splunk"
    type: "splunk"
    index: "browserdefense-demo"
```

---

## Editing Notes

- Keep cuts tight, no dead air
- Add subtle zoom on key UI elements (IOC count, block page URL, Splunk fields)
- Background music: subtle, professional, not distracting
- Lower thirds for key terms (IOC, Zero-Knowledge, Connector)
- Include keyboard shortcut callouts if applicable

---

## Thumbnail Ideas

1. **Split image:** Analyst looking concerned (left) / Block page (right)
2. **Text overlay:** "Block Phishing in 5 Seconds"
3. **Visual:** Chrome extension icon with shield/checkmark overlay
4. **Color scheme:** Red (threat) transitioning to green (blocked)

---

## SEO / Video Metadata

**Title:** BrowserDefense Demo: Block Phishing URLs in 5 Seconds with Zero-Knowledge Forensics

**Description:**
```
See how BrowserDefense blocks malicious URLs at the browser level and captures forensic evidence automatically.

In this demo:
00:00 - Introduction
00:45 - The BrowserDefense Extension
02:00 - Blocking a Phishing URL
03:30 - Forensics Capture
04:45 - SIEM Integration with Splunk
06:00 - Recap and Getting Started

Get BrowserDefense: https://browserdefense.com
GitHub: https://github.com/irdbl/browserdefense
Documentation: https://docs.browserdefense.com

BrowserDefense is open source browser-based IOC blocking for SOC teams. No VPN required, zero-knowledge architecture, instant deployment.

#cybersecurity #phishing #SOC #SIEM #threatintel #infosec
```

**Tags:**
- phishing protection
- IOC blocking
- browser security
- SOC tools
- SIEM integration
- Splunk
- zero knowledge security
- chrome extension security
- threat intelligence
- incident response
- BrowserDefense
