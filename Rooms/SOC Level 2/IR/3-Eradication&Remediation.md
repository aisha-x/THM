# TryHackMe: Eradication & Remediation Room Summary

# Introduction

The previous couple of rooms, which explored the feedback loop between Identification and Scoping and the consequent role of Containment and Threat Intelligence creation in driving the Incident Response process forward, are doing wonders for the incident we’re currently handling. However, our job here isn’t done yet.

As far as scoping goes, it seems that we’ve already identified all of the systems that were compromised. These have been consequently contained as well, and the only remaining thing to do is to remove the bad guys from our environment.

There’s no single correct way to move forward in this particular phase of the IR process. It depends on a lot of factors, and we will touch upon some of them throughout the course of the room.

## Table of contents

1. **Key Considerations for the Eradication Phase**
2. **Eradications Techniques**
3. **Remedations** 
4. **Recovery**
5. **Conclusion**

# Considerations

### **Key Considerations for the Eradication Phase**

This phase focuses on removing the threat and recovering from the incident. The text emphasizes that it is critical but prone to major errors if not handled carefully.

### **1. Critical Warning: Do Not Rush into Eradication**

- **The Mistake:** There is often pressure to jump into eradication before fully understanding the incident. This is usually driven by fear of further data loss.
- **The Consequences:** Acting too soon can backfire severely:
    - It alerts the attacker, potentially causing them to accelerate data theft, destroy systems, or spread further into the network.
    - It can create a frustrating "whack-a-mole" cycle where the threat keeps reappearing in different parts of the network because it wasn't fully scoped.
- **The Solution:** **Complete the scoping phase first.** A full understanding of the threat actor and the extent of the damage is essential for a successful eradication.

### **2. Be Prepared for Setbacks**

- **Initial Failure is Common:** Even with perfect scoping, the first attempt at eradication might fail. This is normal and should be used as a **feedback loop** to improve scoping and try again.
- **Expect Repeated Attacks:** Successful remediation does not mean the threat is gone forever. Expect the same threat actor to return with more sophisticated and harder-to-detect methods.

### **3. The Twofold Main Goal**

The eradication phase must achieve two primary objectives:

1. **Eradicate the Threat:** Prioritize which compromised systems to clean first based on their criticality to the business.
2. **Recover Business Operations:** Restore normal business functions and recover from the impact of the attack.

**Overall Message:** Eradication is a delicate process. Success depends on **thorough prior scoping, patience, and a cyclical approach** that uses feedback from failures to eventually develop and implement an effective plan. Trust the process.

# **Eradication Techniques**

### **Eradication Techniques**

This section outlines three primary methods for removing a threat from compromised systems, each with its own advantages and ideal use cases.

### **1. Automated Eradication**

- **How it works:** Relies on security tools like Anti-Virus (AV) and Endpoint Detection and Response (EDR) to automatically quarantine and remove malware.
- **Best for:** Common, less sophisticated threats that use well-known malware.
- **Limitations:** Ineffective against unique, targeted, or sophisticated threats designed to bypass these tools. **Should not be relied upon as the sole method** for serious incidents.
- **Advantage:** Frees up analysts to focus on more complex threats.

### **2. Complete System Rebuild**

- **How it works:** The most thorough method. The infected system is completely wiped and rebuilt from scratch, guaranteeing a clean slate.
- **Pros:** Ensures complete removal of all attacker traces.
- **Cons:**
    - **Absolute:** Removes everything, both good and bad, requiring a full reinstall of applications, reconfiguration, and data restoration.
    - **Causes Downtime:** The primary drawback. The required downtime often makes this approach impossible for business-critical systems where even minutes of outage are too costly.

### **3. Targeted System Cleanup**

- **How it works:** A precise, surgical approach where only the specific malicious files, artifacts, and persistence mechanisms are removed.
- **When to use:** In highly sensitive cases where:
    - Alerting the attacker would be disastrous (e.g., causing them to destroy data).
    - System downtime is absolutely not an option.
- **Critical Requirement:** This method is **heavily reliant on excellent scoping**. It requires precise intelligence on what the attacker did and where they left traces to be successful. Rushing into this without full knowledge will lead to failure.

**Overall Message:** The choice of technique is a strategic decision based on the **threat's sophistication** and the **business criticality** of the compromised system. There is a direct trade-off between thoroughness (rebuild) and the need to avoid downtime or alerting the attacker (targeted cleanup).

# Remediation

### **The Remediation Phase**

Remediation is the critical follow-up to eradication. It focuses on **fixing the root causes** of the incident to prevent the same compromise from happening again. It's about learning from the attack to build a stronger security posture.

The key insight is that remediation should be **planned alongside eradication and recovery** and executed in a coordinated manner for maximum effectiveness.

### **Key Remediation Strategies:**

The phase involves implementing long-term security improvements based on lessons learned during the incident. Key areas include:

**1. Network Segmentation**

- **Goal:** Reduce the attack surface.
- **Action:** Design the network to allow **only necessary communication** between systems and subnets. This limits a threat actor's ability to move laterally.
- **Bonus:** Improved segmentation also enhances **visibility**, making it easier to detect suspicious network traffic.

**2. Identity and Access Management (IAM) Review**

This is a two-part process focused on the **principle of least privilege**:

- **For Compromised Accounts:** Review and restrict access for any account that was breached. Fix the method of compromise (e.g., reset plaintext passwords, patch vulnerable applications).
- **For Privileged Accounts:** Strictly control and audit access to powerful accounts (e.g., Domain Admins). Implement a process where access is **requested, approved, time-limited, and only granted for specific needs**. This prevents a single compromised account from granting an attacker "free reign" over the entire network.

**3. Patch Management**

- **Goal:** Eliminate the root cause.
- **Action:** While eradication cleans up the attacker's tools, remediation must **patch the vulnerability** they exploited. This must be done **across the entire environment**, not just on obviously affected machines.
- **Long-term Goal:** Establish a robust patch management system that continuously tracks applications, monitors for new vulnerabilities, and **promptly applies patches** to close security gaps.

**Overall Message:** Remediation transforms the incident response from a reactive cleanup into a proactive strengthening of the organization's defenses. It bridges the gap between what the organization did well during the incident and the weaknesses that were exploited, ensuring the same attack cannot be repeated.

# Recovery

### **The Recovery Phase**

The Recovery phase is the final step where the goal is to **safely restore normal business operations**. It's where the security improvements from remediation are implemented and validated to ensure systems can be brought back online securely and reliably.

### **Key Components of Recovery:**

**1. Continuous Testing and Monitoring**

- **Goal:** Validate that the remediation efforts actually work.
- **Action:** Before reintroducing systems to the production environment, they must be tested through **penetration tests and attack simulations**. This creates a feedback loop to ensure the defenses hold against a similar attack.
- **Ongoing Process:** Testing shouldn't stop after recovery; it must be **continuous** across the entire environment to maintain and improve security posture.

**2. Reliance on Backups**

- **Goal:** Restore systems to a known good state.
- **Action:** Use reliable backups to restore not only **data** but also the **complex configurations and setups** of unique systems. This is especially critical if a system underwent a complete rebuild.
- **Best Practice:** Move beyond documentation; **automate recovery** with scripts and, for cloud environments, maintain **updated baseline images** for fast and consistent restoration.

**3. Action Plan: A Phased Approach**

- Recovery is a **continuous process, not a single event**. It requires a structured plan broken into phases:
    - **Near-term:** Implement the most critical fixes immediately to provide immediate value and reduce risk.
    - **Mid-term & Long-term:** Address more complex changes that require coordination between multiple teams and executive approval.
- The message is: **It's not a race.** A deliberate, phased approach is more sustainable and effective than trying to do everything at once.

**Overall Message:** Recovery is about **trust and verification**. It’s the process of carefully validating that the environment is secure, using backups to restore functionality, and executing a practical plan to return to normal operations without rushing, ensuring the incident does not immediately repeat.

# Conclusion

### **The Cycle of Resilient Incident Response**

The incident response process, as detailed in these phases, is not a linear checklist but a continuous, interconnected cycle aimed at achieving resilience. The key takeaway is that success hinges on **deliberate action, learning, and long-term strengthening**, not just on the immediate removal of a threat.

Here are the core unifying principles:

**1. Foundation in Scoping: Patience is Paramount.**

Rushing to eradicate a threat before fully understanding it is the most common and critical error. Thorough scoping—knowing the adversary, their tools, and their full impact—is the non-negotiable foundation that every subsequent phase depends on. Without it, efforts become a futile game of "whack-a-mole."

**2. Strategic Eradication: Balance Thoroughness with Business Reality.**

The choice of eradication technique (Automated, Rebuild, or Targeted) is a strategic decision. It requires balancing the **need for a guaranteed clean slate** with the **business imperative of minimizing downtime** and the **tactical need to avoid alerting a sophisticated adversary.** There is no one-size-fits-all solution.

**3. Beyond Removal: Remediation Addresses the Root Cause.**

Eradication removes the attacker, but Remediation fixes the vulnerabilities that let them in. This phase translates lessons learned into concrete security improvements: strengthening **network segmentation**, enforcing **least privilege access**, and establishing a robust **patch management** program. It’s about ensuring the same attack cannot happen again.

**4. Recovery is Validation and Continuous Improvement.**

Recovery is the safe return to normal operations, built on verification, not assumption. It requires **testing defenses** through simulations, relying on ** reliable backups**, and executing a **phased action plan**. Most importantly, it formalizes the feedback loop, emphasizing that incident response is a continuous process of testing, learning, and adapting.

**Final Synthesis:** An effective incident response transforms a security breach from a disruptive failure into a powerful catalyst for improvement. It demands a methodical approach that values deep understanding over speedy reaction, prioritizes long-term security hardening over short-term fixes, and embeds a culture of continuous learning into the organization's very fabric. The ultimate goal is not just to survive an attack, but to emerge from it stronger and more resilient.
