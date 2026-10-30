package discovery

// Static vScanner platform catalogue and CSPM provider setup steps.
// Content is sourced from UI 2 content.js / Scanner-Onboarding-Product-Research.md.
// No Rendall calls — this is doc-sourced guidance the assistant hands to the customer.

// VscanPlatform is one hypervisor / cloud platform a vScanner can be deployed to.
type VscanPlatform struct {
	Name        string       `json:"name"`
	Sizing      string       `json:"sizing"`
	ImageSource string       `json:"imageSource"`
	Gotchas     string       `json:"gotchas,omitempty"`
	DeploySteps []GuideStep  `json:"deploySteps"`
	ConsoleTip  string       `json:"consoleTip"`
}

// VscanPlatformCatalogue is the full list of supported vScanner platforms.
type VscanPlatformCatalogue struct {
	Platforms []VscanPlatform `json:"platforms"`
	// ConsoleSteps are the serial-console config steps shared by every platform.
	ConsoleSteps []string `json:"consoleSteps"`
}

// GuideStep is one step in a multi-step setup guide.
type GuideStep struct {
	Title string `json:"title"`
	Desc  string `json:"desc"`
	// HasForm signals that this step requires real data from the customer before
	// they can confirm it (e.g. providing account details to Arctic Wolf).
	HasForm bool `json:"hasForm,omitempty"`
}

var vscanConsoleSteps = []string{
	"Open the VM console and press Enter three times to start.",
	"Choose DHCP (with a DHCP reservation recommended) or enter a Static IP for the management interface.",
	"Answer \"No\" to the proxy question (proxies are not supported for scanners).",
	"Optionally run the connectivity test; fix any failing checks before continuing.",
	"Enter a short name and choose \"Scanner\" as the role.",
	"Scan the QR code or open the pairing URL shown (valid 15 minutes) to connect it to Arctic Wolf.",
}

var vscanPlatforms = []VscanPlatform{
	{
		Name:        "AWS",
		Sizing:      "c5n.2xlarge",
		ImageSource: "Private AMI \"Arctic Wolf Appliance-<version>\" (visible after Cloud Sensors Add Account, up to 24h)",
		Gotchas:     "AWS AUP restricts vulnerability scanning — this is the Arctic Wolf-sanctioned path. GuardDuty will flag the vScanner as malware — create a suppression rule. Cannot reconfigure a deployed AWS vScanner — delete and redeploy if settings change.",
		DeploySteps: []GuideStep{
			{Title: "Provide your AWS account ID to Arctic Wolf", Desc: "In Unified Portal: Data Collection > Cloud Sensors > Add Account > click \"Arctic Wolf AWS Appliance VM\". Enter your Account Name and Account ID, then Test and Submit Credentials. The vScanner AMI can take up to 24 hours to appear in your account.", HasForm: true},
			{Title: "Launch instance from the private AMI", Desc: "In EC2, launch an instance from the private AMI \"Arctic Wolf Appliance-<version>\" (filter Images > AMIs by Private images). Select instance type c5n.2xlarge. Do not select a key pair."},
			{Title: "Enable Termination Protection", Desc: "Under Advanced details, enable Termination Protection to prevent accidental deletion."},
			{Title: "Configure networking", Desc: "Use a private subnet (recommended) and disable auto-assign public IP."},
			{Title: "Configure security group", Desc: "Remove all inbound rules; allow all outbound traffic."},
			{Title: "Launch and enable Serial Console", Desc: "Launch the instance. If not already enabled, turn on the EC2 Serial Console account attribute, then connect via EC2 Serial Console."},
		},
	},
	{
		Name:        "Azure (standard)",
		Sizing:      "Standard_D4as_v5 (4 vCPU / 16 GB) — exact size required, fall back to v7 then v4 if v5 unsupported in region",
		ImageSource: "Azure Marketplace private plan: My Marketplace > Private plans > \"AWN - Virtual Appliance\"",
		Gotchas:     "Requires Cloud Sensors Add Account first with Subscription ID (up to 24h to appear). Microsoft Defender for Cloud Apps flags it as malware — add a suppression rule.",
		DeploySteps: []GuideStep{
			{Title: "Provide your Azure account information to Arctic Wolf", Desc: "In Unified Portal: Data Collection > Cloud Sensors > Add Account > click \"Arctic Wolf Azure Appliance VM\". Enter Account Name, Subscription ID, and optional Credential Expiry, then Test and Submit Credentials. Wait for the account to appear (up to 24h).", HasForm: true},
			{Title: "Create VM from the private plan", Desc: "My Marketplace > Private plans > \"AWN - Virtual Appliance\" > Create. Select Standard security type, size Standard_D4as_v5."},
			{Title: "Configure disk and networking", Desc: "Standard SSD disk. No public IP, no inbound ports open."},
			{Title: "Download (and discard) the key pair", Desc: "Azure auto-generates a key pair — Arctic Wolf doesn't use it. Safe to download and delete."},
			{Title: "Connect via serial console", Desc: "Connect > More ways to connect > Serial console."},
		},
	},
	{
		Name:        "Azure (CSP, direct share)",
		Sizing:      "Standard_D4as_v5 (4 vCPU / 16 GB) — same as standard Azure",
		ImageSource: "Image received via Azure Direct share (Images > See all images > Direct share, scoped to your Subscription ID)",
		Gotchas:     "Only applies if you have a Cloud Solution Provider (CSP) plan and received the image via direct share.",
		DeploySteps: []GuideStep{
			{Title: "Locate the direct-shared image", Desc: "In Images, click \"See all images\" > Direct share, scoped to your Subscription ID."},
			{Title: "Create VM from the shared image", Desc: "Standard security type, size Standard_D4as_v5, Standard SSD disk, no public IP, no inbound ports."},
			{Title: "Download (and discard) the key pair", Desc: "Unused by Arctic Wolf — safe to delete."},
			{Title: "Connect via serial console", Desc: "Connect > More ways to connect > Serial console."},
		},
	},
	{
		Name:        "Azure (CSP, manual upload)",
		Sizing:      "Standard_D4as_v5 (4 vCPU / 16 GB) — same as standard Azure",
		ImageSource: "Password-protected VHD zip from Arctic Wolf (≥40 GB free space to extract; macOS needs CLI unzip)",
		Gotchas:     "Most involved path — three extra substeps before VM creation. Only applies on CSP plans without direct-share access.",
		DeploySteps: []GuideStep{
			{Title: "Download and extract the VHD", Desc: "Get the password-protected VHD zip from Arctic Wolf. Needs ≥40 GB free space; on macOS extract via CLI (unzip), not Finder."},
			{Title: "Upload the VHD to Azure Blob Storage", Desc: "Create or use a storage account/container and upload the extracted VHD file."},
			{Title: "Build a Custom Image from the blob", Desc: "OS type Linux, Gen 1, Standard SSD, Read/write host caching."},
			{Title: "Create the VM from the custom image", Desc: "Standard security type, size Standard_D4as_v5, no public IP, no inbound ports."},
			{Title: "Connect via serial console", Desc: "Connect > More ways to connect > Serial console."},
		},
	},
	{
		Name:        "Microsoft Hyper-V",
		Sizing:      "8 vCPU / 16 GB RAM / 40 GB storage; Hyper-V Server 2016+",
		ImageSource: "Download OVA from Unified Portal: Resources > Downloads > Virtual Network Appliances > Hyper-V tab (.ovf → rename to .ova if needed)",
		Gotchas:     "Must import the entire VM from template, not just the disk, or sizing won't match requirements. Don't throttle CPU — can cause lost security observations.",
		DeploySteps: []GuideStep{
			{Title: "Download the appliance template", Desc: "Resources > Downloads > Virtual Network Appliances > Hyper-V tab. Rename .ovf to .ova if your browser downloaded it that way."},
			{Title: "Import the entire VM from template", Desc: "Use Hyper-V Manager's Import Virtual Machine wizard on the full template — it already sets CPU/RAM/NIC correctly."},
			{Title: "Copy as a new unique ID", Desc: "Select \"Copy the virtual machine\" during import so it gets a fresh unique ID."},
			{Title: "Connect network adapter", Desc: "Attach the VM's network adapter to an existing virtual switch."},
			{Title: "Power on and open console", Desc: "Start the VM, then double-click it in Hyper-V Manager to open the console."},
		},
	},
	{
		Name:        "Nutanix Prism Central",
		Sizing:      "8 vCPU (1 core/CPU) / 16 GB RAM / 40 GB storage",
		ImageSource: "Download OVA from Unified Portal: Resources > Downloads > VMware/Nutanix tab; copy the SHA-256 checksum shown",
		Gotchas:     "Checksum must match on upload or it fails. Same CPU-throttling warning as Hyper-V.",
		DeploySteps: []GuideStep{
			{Title: "Download the OVA and copy checksum", Desc: "Resources > Downloads > VMware/Nutanix tab. Copy the SHA-256 checksum shown alongside the download."},
			{Title: "Upload the OVA", Desc: "Compute & Storage > OVAs > Upload OVAs, pasting the checksum to verify."},
			{Title: "Deploy as VM", Desc: "From the uploaded OVA, Deploy as VM; set CPU/cores/memory manually to 8 vCPU / 16 GB."},
			{Title: "Select subnet and clean up NICs", Desc: "Select the target subnet; remove any unused network rows."},
			{Title: "Create, power on and launch console", Desc: "Create VM, Power On, then Launch Console."},
		},
	},
	{
		Name:        "Nutanix Prism Element",
		Sizing:      "8 vCPU / 16 GB RAM / 40 GB storage",
		ImageSource: "Same OVA as Prism Central, but must be extracted locally first (Windows needs 7-Zip/WinRAR; OVA contains a .vmdk)",
		Gotchas:     "Only Prism Element requires manual OVA extraction. Legacy BIOS boot config may be needed.",
		DeploySteps: []GuideStep{
			{Title: "Download and extract the OVA locally", Desc: "Resources > Downloads > VMware/Nutanix tab. Extract locally (Windows needs 7-Zip or WinRAR) to get the .vmdk file inside."},
			{Title: "Upload the image", Desc: "Image Configuration > Upload Image, type DISK, upload the extracted .vmdk."},
			{Title: "Create VM and attach the disk", Desc: "Create VM, remove the default disk, add a new disk cloned from the uploaded image."},
			{Title: "Add NIC on target subnet", Desc: "Attach a NIC to the correct subnet; set Legacy BIOS boot config if needed."},
			{Title: "Save, power on and launch console", Desc: "Save the VM, Power On, then Launch Console."},
		},
	},
	{
		Name:        "Standalone ESXi",
		Sizing:      "8 vCPU / 16 GB RAM / 40 GB storage; ESXi 6.5+",
		ImageSource: "Download OVA from Unified Portal: Resources > Downloads > VMware/Nutanix tab",
		Gotchas:     "Give the VM a name that was never used before on this host — a reused name is a documented activation blocker.",
		DeploySteps: []GuideStep{
			{Title: "Download the OVA", Desc: "Resources > Downloads > VMware/Nutanix tab."},
			{Title: "Create/Register VM from OVF/OVA", Desc: "In the ESXi web UI, Create/Register VM > Deploy from OVF/OVA file."},
			{Title: "Choose a never-used VM name", Desc: "Reused names block activation — pick a name that has not been used on this host before."},
			{Title: "Select deployment type", Desc: "Set Deployment type to \"AWN Risk Scanner\"."},
			{Title: "Finish, power on and open console", Desc: "Finish the wizard, Power On, then Open Console."},
		},
	},
	{
		Name:        "VMware vSphere",
		Sizing:      "8 vCPU / 16 GB RAM / 40 GB storage; vSphere/vCenter 6.5+",
		ImageSource: "Same OVA as ESXi, from Unified Portal Downloads",
		Gotchas:     "Only the vSphere flow offers an explicit \"encrypt this VM\" option — Arctic Wolf recommends enabling it.",
		DeploySteps: []GuideStep{
			{Title: "Download the OVA", Desc: "Resources > Downloads > VMware/Nutanix tab (same OVA as ESXi)."},
			{Title: "Deploy OVF Template", Desc: "Right-click the target resource pool > Deploy OVF Template, upload the local file."},
			{Title: "Select compute resource and storage", Desc: "Choose the destination compute resource and datastore."},
			{Title: "Set deployment type and optionally encrypt", Desc: "Configuration: \"AWN Risk Scanner\". Arctic Wolf recommends enabling \"Encrypt this VM\" if available."},
			{Title: "Select network, finish and verify", Desc: "Pick the destination network, finish, then verify the VM is powered on and has an IP before opening the console."},
		},
	},
}

// VscanPlatformCatalogue returns the full list of supported vScanner platforms with
// per-platform deploy steps and the shared serial-console config sequence.
func VscanPlatforms() VscanPlatformCatalogue {
	return VscanPlatformCatalogue{Platforms: vscanPlatforms, ConsoleSteps: vscanConsoleSteps}
}

// --- CSPM provider setup steps ---

// CspmProvider is one cloud provider and the manual steps to set up read-only access for CSPM.
type CspmProvider struct {
	Key              string      `json:"key"` // aws | azure | gcp
	Label            string      `json:"label"`
	OtherMethodsNote string      `json:"otherMethodsNote,omitempty"`
	ManualSteps      []GuideStep `json:"manualSteps"`
	// CredentialFields are the fields the customer submits to Arctic Wolf after setup.
	CredentialFields []CspmField `json:"credentialFields"`
}

// CspmField is one credential field the customer provides after completing provider setup.
type CspmField struct {
	Key         string `json:"key"`
	Label       string `json:"label"`
	Placeholder string `json:"placeholder,omitempty"`
	Hint        string `json:"hint,omitempty"`
	Sensitive   bool   `json:"sensitive,omitempty"`
	ReadOnly    bool   `json:"readOnly,omitempty"` // primary identifier — can't be updated later
}

// CspmProviderCatalogue holds all supported CSPM providers.
type CspmProviderCatalogue struct {
	Providers []CspmProvider `json:"providers"`
	// StatusNote explains the Pending→Active lifecycle after submission.
	StatusNote string `json:"statusNote"`
}

var cspmProviders = []CspmProvider{
	{
		Key:              "aws",
		Label:            "AWS",
		OtherMethodsNote: "AWS also supports a Terraform script and a CLI method. This guide walks the manual (IAM console) path.",
		ManualSteps: []GuideStep{
			{Title: "Enable Security Token Service (STS)", Desc: "In the AWS IAM console, go to Account settings. In the Security Token Service (STS) section, find your AWS region (listed on the Arctic Wolf Unified Portal Allowlist Requirements page, Cloud Infrastructure Scans section) and set it to Active."},
			{Title: "Determine the Arctic Wolf AWS account ID", Desc: "In Unified Portal: Resources > Allowlist Requirements > Cloud Infrastructure Scans section > AWS row. Copy the Account ID shown — you'll use it as the trusted account when creating the IAM role."},
			{Title: "Create a new IAM role", Desc: "In the IAM console: Roles > Create role > AWS account > Another AWS account. Enter the Arctic Wolf account ID. Check \"Require external ID\" and enter your own 12-digit AWS account ID as the external ID. Attach the SecurityAudit managed policy. Name the role AWNSecurityAuditRole. Create the role, then copy its Role ARN."},
			{Title: "Create an inline policy on the role", Desc: "On AWNSecurityAuditRole: Add permissions > Create inline policy. Add the additional read-only permissions Arctic Wolf requires (auditmanager:GetSettings, backup:ListBackupPlans, compute-optimizer:GetRecommendationSummaries, and others from the setup guide). Name and create the policy."},
		},
		CredentialFields: []CspmField{
			{Key: "accountName", Label: "Account Name", Placeholder: "A unique, descriptive name"},
			{Key: "accountId", Label: "Account ID", Placeholder: "e.g. 123456789012", Hint: "Your 12-digit AWS account number.", ReadOnly: true},
			{Key: "roleArn", Label: "Role ARN", Placeholder: "arn:aws:iam::123456789012:role/AWNSecurityAuditRole", Hint: "The account number in the ARN should match the Account ID above."},
		},
	},
	{
		Key:              "azure",
		Label:            "Azure",
		OtherMethodsNote: "Azure also supports a Terraform script via Azure Cloud Shell. This guide walks the manual (Entra ID) path.",
		ManualSteps: []GuideStep{
			{Title: "Register the application in Microsoft Entra ID", Desc: "Azure portal: Microsoft Entra ID > Manage > App registrations > + New registration. Name it, keep Single Tenant selected, and Register. Copy the Application (client) ID and Directory (tenant) ID from the overview page."},
			{Title: "Create a client secret", Desc: "On the app: Manage > Certificates & secrets > + New client secret. Set a description and expiration, then Add. Copy the Value immediately — it is only shown once and is the Secret Key Arctic Wolf needs (not the Secret ID)."},
			{Title: "Retrieve the subscription ID", Desc: "In the portal menu, go to Subscriptions and select the subscription you want Arctic Wolf to scan. Copy its Subscription ID."},
			{Title: "Add role assignments", Desc: "On that subscription: Access control (IAM) > Role assignments > + Add role assignment. Assign Security Reader to the application, then repeat and assign Log Analytics Reader to the same application. Verify both roles are listed."},
		},
		CredentialFields: []CspmField{
			{Key: "accountName", Label: "Account Name", Placeholder: "A unique, descriptive name"},
			{Key: "directoryId", Label: "Directory ID", Hint: "From app registration."},
			{Key: "applicationId", Label: "Application ID", Hint: "From app registration."},
			{Key: "subscriptionId", Label: "Subscription ID", Hint: "From Retrieve the subscription ID step.", ReadOnly: true},
			{Key: "secretKey", Label: "Secret Key", Hint: "The client secret Value — only shown once at creation.", Sensitive: true},
		},
	},
	{
		Key:   "gcp",
		Label: "Google Cloud Platform",
		ManualSteps: []GuideStep{
			{Title: "Create a service account", Desc: "In the Google Cloud Console: IAM & admin > Service accounts > Create service account. Name it (e.g. arctic-wolf-service-account). Under Manage Access, add the Viewer role and the Security Reviewer role to the service account."},
			{Title: "Create and download a JSON key", Desc: "On the service account: Actions > Manage keys > Add key > Create new key > JSON > Create. The key file downloads automatically — save it; you'll upload this exact file to Arctic Wolf."},
			{Title: "Enable required APIs in your project", Desc: "In APIs & Services, enable each of these in your project: Compute Engine, Cloud Resource Manager, IAM, Cloud Storage, Cloud Logging, Cloud Monitoring, Cloud DNS, Cloud KMS, GKE, Cloud SQL, BigQuery, Cloud Bigtable, Cloud Spanner, Dataproc, Deployment Manager, Cloud Composer, Artifact Registry, API Gateway, API Keys, Cloud Functions, Cloud Run, Access Context Manager, Access Approval, Cloud Build, and Cloud Identity."},
		},
		CredentialFields: []CspmField{
			{Key: "accountName", Label: "Account Name", Placeholder: "A unique, descriptive name"},
			{Key: "projectId", Label: "Project ID", Hint: "The project_id value from the downloaded JSON file.", ReadOnly: true},
			{Key: "jsonKey", Label: "JSON Credential File", Placeholder: "service-account-key.json", Hint: "The JSON key file downloaded from GCP."},
		},
	},
}

// CspmProviders returns CSPM provider setup steps and credential fields.
func CspmProviders() CspmProviderCatalogue {
	return CspmProviderCatalogue{
		Providers: cspmProviders,
		StatusNote: "After submission: status is Pending (yellow = validating credentials, orange = validation failed). " +
			"A ticket is created for the Concierge Security Team (CST) to finalize. " +
			"Status becomes Active once credentials are validated and CST confirms — CSPM scans start after that.",
	}
}

// --- IVA configure groups ---

// IvaConfigGroup describes one configuration group in the scanner Configure flow.
type IvaConfigGroup struct {
	Key      string          `json:"key"`
	Title    string          `json:"title"`
	Sub      string          `json:"sub,omitempty"`
	Kind     string          `json:"kind"` // toggles | credentialed | exclusions | schedule | upgrade
	Toggles  []IvaToggle     `json:"toggles,omitempty"`
}

// IvaToggle is one switch in a toggle group.
type IvaToggle struct {
	Key         string `json:"key"`
	Label       string `json:"label"`
	Description string `json:"description,omitempty"`
	Default     bool   `json:"default"`
}

var ivaConfigGroups = []IvaConfigGroup{
	{
		Key: "scanBehavior", Title: "Core scan behavior",
		Sub:  "Host identification and vulnerability scanning must both be on for scans to run.",
		Kind: "toggles",
		Toggles: []IvaToggle{
			{Key: "hostId", Label: "Host Identification", Description: "Discovery scan (Nmap-based). Required for vulnerability scanning to work at all.", Default: true},
			{Key: "vulnScan", Label: "Vulnerability Scanning", Description: "The actual IVA vulnerability checks (OpenVAS/NASL-based).", Default: true},
			{Key: "pingOnly", Label: "Ping Only Discovery", Description: "Lighter-weight alternative to full host identification.", Default: false},
			{Key: "selfScan", Label: "Self-Scanning", Description: "Scanner tests itself for vulnerabilities.", Default: false},
		},
	},
	{
		Key: "detectionAddons", Title: "Detection add-ons",
		Sub:  "Troubleshooting toggles for specific scan behaviors.",
		Kind: "toggles",
		Toggles: []IvaToggle{
			{Key: "cgi", Label: "CGI Scanning", Description: "Checks for well-known web app vulnerabilities. Disable temporarily to avoid false-positive lockouts.", Default: true},
			{Key: "bruteForce", Label: "Brute Force Scanning", Description: "Attempts default/common credentials. Recommended on; disable only for emergencies.", Default: true},
		},
	},
	{Key: "credentialed", Title: "Credentialed scanning", Sub: "Authenticate to target systems for deeper checks (missing patches, outdated software).", Kind: "credentialed"},
	{Key: "exclusions", Title: "Exclusions & DNS", Sub: "Scope control: IP addresses or ports you never want scanned (e.g. fragile printers, medical devices, VoIP).", Kind: "exclusions"},
	{Key: "schedules", Title: "Scan schedules", Sub: "Define target, frequency, and time window.", Kind: "schedule"},
	{Key: "upgrades", Title: "Scanner upgrades", Sub: "Appliance software upgrades, default 7 days out from notification.", Kind: "upgrade"},
}

// IvaConfigGroups returns the ordered configure flow groups for physical and virtual scanners.
func IvaConfigGroups() []IvaConfigGroup {
	return ivaConfigGroups
}
