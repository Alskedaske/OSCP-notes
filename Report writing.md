# Report Writing for Penetration Testers
Goal: remind us what occurred and allow to replicate issues

General outline: top-down. E.g.:
- Application name
- URL
- Request type
- Issue detail
- PoC payload

Take screenshots! Always support them with text

Goal of the company should be leading. 
- Customer looks for a path forward that:
  - Outlines all present flaws in systems within scope
  - Ways to fix those flaws immediately
  - Strategic goals that will prevent these vulnerabilities from appearing in the future
 
Do not include too many details on *no vulnerabilities*. Takes away from vulnerabilities that are present.

Be aware of your audience (type of company) and their security concerns, business goals, objectives

Split the report into appropriate sections/subsections depending on the audience (e.g. management and technical staff)

### Executive Summary

High level structure:
- Outline of scope
  - (Timing issues)
- Time frame (length, dates, hours)
- Rules of engagement (referee, specific requirements for test)
- Supporting infrastructure/accounts (attacker IP, accounts granted, accounts created)

Long-form:
- Summarise test steps
- Key findings:
  - Severity
  - Context
  - Worst-case scenario
- Observed trends for strategic advice
  - Group findings with similar vulnerability
- Mention positives
- Engagement wrap-up

### Full report
After executive summary we provide more info:
- Testing environment considerations (were there issues that affected the testing?)
- Technical summary (summary of key findings for technical person)
  - Group findings into common areas!
  - Finish with risk heat map - based on vulnerability, adjusted for client's context. 
- Technical findings and recommendations
  - Often in a table (columns: Reference, risk, issue description and implications, recommandations)
  - May be need for an attack narrative (write out the attack step-by-step)
  - Use technical severity here (do not adjust for context-specific business risk)
  - First: short description of what the vulnerability is, why it is dangerous, what can be accomplished
  - Second: evidence (simple: in text, more complex: appendix)
  - Third: remediation advice: detailed enough so that it can be implemented acceptably by the client (no excessive cost/culturally inappropriate)
 
Important:
- Avoid broad solutions
- Make solutions concrete and practical
- Each step should be 1 solution, not multiple steps in 1 solution

### Appendices, Further Information, and References
Anything that does not fit anywhere else/too long/too detailed

Appendix: if it is necessary for the report but would break the flow of the page

Further information: Not necessary but could provide value (article with in-depth description of vulnerability, standards to follow for remediation, etc.)

References: sources

