# ⚠️ Disclaimer & Liability Limitation

**Use at your own risk.** The code, workflows, and scripts provided in this repository (`n8n-hubspot-gdpr-ccpa-consent-preference-sync`) are for educational and architectural demonstration purposes. They are not legal advice, and they are not a substitute for a privacy program designed with qualified counsel.

* **No Liability:** The author and dhRobin Systems assume no responsibility or liability for any direct, indirect, incidental, or consequential damages resulting from the use, misuse, or deployment of these scripts, including compliance breaches, regulatory fines, complaints to supervisory authorities, consumer claims, misapplied or missed opt-outs, incorrect subscription status, and data loss.
* **No Warranty:** All software, n8n JSON blueprints, and JavaScript modules are provided "AS IS" without warranty of any kind, express or implied, including but not limited to merchantability, fitness for a particular purpose, or non-infringement. Consent platform payloads, HubSpot APIs, and n8n node parameters change over time; the provider mappings shipped here are illustrative and must be verified against your own payloads.
* **Production Testing Required:** Always test thoroughly in an isolated staging environment (for example a HubSpot developer test account or sandbox) with `SANDBOX_MODE=true` and `DRY_RUN=true` enabled before connecting live HubSpot credentials. Treat every unsubscribe, global opt-out, and processing restriction as something that cannot be undone, and review every planned change in dry run first.
* **Third-Party APIs & Compliance:** Users are solely responsible for complying with the terms of service, rate limits, data privacy regulations (GDPR / UK GDPR, CCPA / CPRA, ePrivacy / PECR, CAN-SPAM, and other regional laws), and security policies of HubSpot, their consent management platform, and any connected services. That includes deciding which jurisdictions and consent models apply, mapping each banner category to the correct legal effect, honouring Global Privacy Control where required, keeping consent records and audit trails for the required periods, securing the webhook relay and its signing secret, and reviewing every automated subscription and property change.
* **Cookie Consent Is Not Email Consent:** Accepting marketing cookies does not, by itself, establish consent to receive marketing email. This software never subscribes a contact; any opt-in to email must be collected and evidenced separately.
* **Data Minimization:** The audit log stores a pseudonymous hash, not the email address. A hash is pseudonymous data, not anonymous data, and remains personal data under GDPR.

## Limitation of Liability

To the maximum extent permitted by law, in no event shall dhRobin Systems or the author (DH Robin) be liable for any claim, damages, fines, or other liability, whether in an action of contract, tort, or otherwise, arising from, out of, or in connection with this software or its use, even if advised of the possibility of such damage.

## License

Released under the MIT License. Copyright (c) 2026 DH Robin (dhRobin Systems). See [LICENSE](https://github.com/dhrobinsystems/n8n-hubspot-gdpr-ccpa-consent-preference-sync/blob/main/LICENSE).

---

> DISCLAIMER: Provided as-is without warranty of any kind, express or implied. The author and dhRobin Systems shall not be held liable for any compliance breaches, regulatory fines, data loss, or damages arising from the use of this code or workflow. Users are solely responsible for verifying their own legal and regulatory compliance posture under GDPR, CCPA, and applicable privacy laws.
> 
> Full text: DISCLAIMER.md · Licensed under the MIT License. License: MIT © 2026 dhRobin Systems · Provided as-is, see the disclaimer.
