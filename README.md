# Power Platform Enterprise Gap Assessment

A PowerShell script to perform a **comprehensive security and compliance gap assessment** of Microsoft Power Platform environments (Power Apps, Power Automate, Power BI, Dataverse) aligned with **ISO/IEC 27001** and **CIS Microsoft Power Platform Benchmark v1.0+**.

![Power Platform Assessment](https://img.shields.io/badge/PowerPlatform-Security_Assessment-blue)
![PowerShell](https://img.shields.io/badge/PowerShell-7.0%2B-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## ✨ Features

- ✅ Assess **Security Model**: DLP policies, default environments, audit logging
- ✅ Evaluate **Architecture**: Dataverse solutions, entity count, data model
- ✅ Analyze **Power Automate Flows**: Custom connectors, usage patterns
- ✅ Review **Power Apps**: Component reusability, screen count, sharing
- ✅ Audit **Power BI**: Workspace sensitivity labels, ad-hoc workspaces
- ✅ Check **Licensing & Hierarchy**
- 📊 Generate **HTML report** with **risks, impacts, mitigations**, and **ISO 27001 / CIS mappings**
- 🔐 **No service principal required** — uses interactive Global Admin authentication

---

## ⚠️ Prerequisites

### 1. **Account Permissions**
You must sign in with a user account that has:
- **Global Administrator** **OR**
- **Power Platform Administrator** + **Power BI Administrator** + **Security Reader** roles in Microsoft Entra ID (Azure AD)

> 💡 **Important**: The first run **must** be done after activating Power Platform APIs (see **"First-Time Setup"** below).

### 2. **PowerShell Version**
- **Windows PowerShell 5.1** *(recommended for full module compatibility)*  
  **OR**
- **PowerShell 7.2+** *(may require workarounds for some cmdlets)*

> 🔗 [Install PowerShell 7](https://aka.ms/powershell-release?tag=stable)

### 3. **Required PowerShell Modules**
Run the following in **PowerShell as Administrator**:

```powershell
# Install required modules
Install-Module Microsoft.PowerApps.Administration.PowerShell -Force -AllowClobber -Scope CurrentUser
Install-Module MicrosoftPowerBIMgmt.Admin -Force -AllowClobber -Scope CurrentUser
Install-Module Microsoft.Graph -Force -AllowClobber -Scope CurrentUser


### 4. **📊Output**
The script produces a professional HTML report that includes:

Executive Summary: Tenant ID, assessment date, total findings
Detailed Findings by category:
Security Model & Accessibility
Design, Data Model & Architecture
Flow, Formula & Optimization
Component Reusability
Dashboard & Analytics
Application Performance
License & Hierarchy
For each finding:
🔴 Risk level (Critical/High/Medium/Low)
📌 Business impact
🛠️ Mitigation guidance
📚 ISO/IEC 27001 control mapping
📋 CIS Benchmark reference
🔍 Evidence (e.g., environment name, policy ID)

### 5. **⚠️ Known Limitations**
Get-AdminPowerPlatformEnvironment may fail in PowerShell 7 due to .NET compatibility issues. Use Windows PowerShell 5.1 for best results.
Some Dataverse entity counts require additional API permissions.
Audit log validation may require manual confirmation in the Microsoft 365 Compliance Center.

🔒 Security Note
This script uses interactive authentication and does not store credentials. All data is processed locally and never sent to external services.

📄 License
This project is licensed under the MIT License — see the LICENSE file for details.

### 6. **▶️ How to Run**
Open PowerShell as Administrator
Navigate to the script directory
powershell


1
cd C:\Path\To\Script
Run the script
powershell


1
.\PowerPlatform-EnterpriseGapAssessment.ps1
Sign in when prompted with your Global Admin account
📁 The script generates an HTML report in the same directory (e.g., PowerPlatform_Enterprise_GapAssessment_20251124_1230.html) 

