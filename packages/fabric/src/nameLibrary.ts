/**
 * Name and vocabulary pools for enterprise generation.
 *
 * These exist so a generated organization reads like a real company rather
 * than like `user-17` repeated four hundred times. Nothing here is random at
 * runtime; every selection is driven by a RandomCursor so the same seed
 * always produces the same staff list.
 */

export const GIVEN_NAMES: readonly string[] =
  [
    "Sarah", "Mark", "Jordan", "Priya",
    "Daniel", "Aisha", "Tomas", "Lena",
    "Victor", "Amara", "Chen", "Ravi",
    "Marta", "Owen", "Freya", "Diego",
    "Nadia", "Elliot", "Yuki", "Samuel",
    "Ingrid", "Hassan", "Claire", "Mateo",
    "Rosa", "Karl", "Anika", "Julian",
    "Farah", "Peter", "Simone", "Andre",
    "Leila", "Gregor", "Maya", "Benedict",
    "Oksana", "Rahim", "Bianca", "Stefan",
    "Noor", "Colin", "Talia", "Emeka",
    "Helena", "Rasmus", "Divya", "Oscar",
    "Camille", "Idris", "Renata", "Hugo",
  ];

export const FAMILY_NAMES: readonly string[] =
  [
    "Martinez", "Chen", "Lee", "Okafor",
    "Novak", "Haddad", "Bergstrom", "Silva",
    "Petrov", "Nakamura", "OConnell", "Adeyemi",
    "Kowalski", "Rahman", "Dubois", "Ferreira",
    "Lindqvist", "Vargas", "Ibrahim", "Schneider",
    "Kaur", "Moreau", "Rossi", "Andersen",
    "Mbeki", "Fischer", "Delgado", "Novotny",
    "Yilmaz", "Wallace", "Cortes", "Bianchi",
    "Halvorsen", "Nguyen", "Shigeru", "Brennan",
    "Sorensen", "Achebe", "Marchetti", "Pires",
  ];

export interface DepartmentProfile {
  readonly name: string;

  /** Relative headcount weight against the other departments. */
  readonly weight: number;

  /** Third octet of the department subnet, e.g. 10.20.<octet>.x */
  readonly subnetOctet: number;

  /** Short code used in hostnames, e.g. FIN-LT-04. */
  readonly hostCode: string;

  readonly titles: readonly string[];

  /** Directory groups every member of the department receives. */
  readonly baseRoles: readonly string[];

  /**
   * How business-critical the department's assets are. Feeds asset
   * criticality, which drives triage priority in the Ops tools.
   */
  readonly criticality:
    | "low"
    | "moderate"
    | "high"
    | "severe";
}

export const DEPARTMENT_PROFILES: readonly DepartmentProfile[] =
  [
    {
      name: "Finance",
      weight: 16,
      subnetOctet: 20,
      hostCode: "FIN",
      titles: [
        "Financial Analyst",
        "Senior Financial Analyst",
        "Accounts Payable Specialist",
        "Controller",
        "Treasury Analyst",
        "Finance Manager",
      ],
      baseRoles: [
        "domain-users",
        "finance-staff",
      ],
      criticality: "severe",
    },
    {
      name: "Human Resources",
      weight: 9,
      subnetOctet: 21,
      hostCode: "HR",
      titles: [
        "HR Business Partner",
        "Recruiter",
        "People Operations Specialist",
        "Compensation Analyst",
        "HR Director",
      ],
      baseRoles: [
        "domain-users",
        "hr-staff",
      ],
      criticality: "high",
    },
    {
      name: "Information Technology",
      weight: 14,
      subnetOctet: 30,
      hostCode: "IT",
      titles: [
        "Systems Administrator",
        "Service Desk Analyst",
        "Network Engineer",
        "Cloud Engineer",
        "IT Manager",
        "Database Administrator",
      ],
      baseRoles: [
        "domain-users",
        "it-staff",
      ],
      criticality: "severe",
    },
    {
      name: "Security",
      weight: 8,
      subnetOctet: 31,
      hostCode: "SEC",
      titles: [
        "Security Analyst",
        "Senior Security Analyst",
        "Detection Engineer",
        "Incident Responder",
        "Security Engineer",
        "SOC Manager",
      ],
      baseRoles: [
        "domain-users",
        "security-staff",
      ],
      criticality: "severe",
    },
    {
      name: "Engineering",
      weight: 24,
      subnetOctet: 40,
      hostCode: "ENG",
      titles: [
        "Software Engineer",
        "Senior Software Engineer",
        "Staff Engineer",
        "Engineering Manager",
        "QA Engineer",
        "Site Reliability Engineer",
      ],
      baseRoles: [
        "domain-users",
        "engineering-staff",
      ],
      criticality: "high",
    },
    {
      name: "Sales",
      weight: 18,
      subnetOctet: 50,
      hostCode: "SLS",
      titles: [
        "Account Executive",
        "Sales Development Representative",
        "Regional Sales Manager",
        "Solutions Consultant",
      ],
      baseRoles: [
        "domain-users",
        "sales-staff",
      ],
      criticality: "moderate",
    },
    {
      name: "Marketing",
      weight: 8,
      subnetOctet: 51,
      hostCode: "MKT",
      titles: [
        "Marketing Manager",
        "Content Strategist",
        "Demand Generation Specialist",
        "Brand Manager",
      ],
      baseRoles: [
        "domain-users",
        "marketing-staff",
      ],
      criticality: "low",
    },
    {
      name: "Legal",
      weight: 5,
      subnetOctet: 22,
      hostCode: "LGL",
      titles: [
        "Corporate Counsel",
        "Paralegal",
        "Compliance Officer",
      ],
      baseRoles: [
        "domain-users",
        "legal-staff",
      ],
      criticality: "high",
    },
    {
      name: "Executive",
      weight: 4,
      subnetOctet: 10,
      hostCode: "EXE",
      titles: [
        "Chief Executive Officer",
        "Chief Financial Officer",
        "Chief Information Officer",
        "Chief Information Security Officer",
        "Chief Operating Officer",
      ],
      baseRoles: [
        "domain-users",
        "executive-staff",
      ],
      criticality: "severe",
    },
  ];

/** Directory groups that elevate an account beyond ordinary staff access. */
export const PRIVILEGED_ROLES: readonly string[] =
  [
    "domain-admins",
    "server-operators",
    "backup-operators",
    "helpdesk-admins",
    "cloud-administrators",
    "security-administrators",
  ];

export const WORKSTATION_OPERATING_SYSTEMS: readonly string[] =
  [
    "Windows 11 Enterprise 23H2",
    "Windows 11 Enterprise 24H2",
    "Windows 10 Enterprise 22H2",
    "macOS 15.2 Sequoia",
    "macOS 14.7 Sonoma",
    "Ubuntu 24.04 LTS",
  ];

export const SERVER_OPERATING_SYSTEMS: readonly string[] =
  [
    "Windows Server 2022 Datacenter",
    "Windows Server 2019 Standard",
    "Ubuntu Server 22.04 LTS",
    "Red Hat Enterprise Linux 9.4",
  ];

export type ServerPlatform =
  | "windows"
  | "linux"
  | "any";

export interface ServerProfile {
  readonly hostname: string;
  readonly role: string;
  /**
   * Constrains the OS pool. Domain controllers and the SMB file server must
   * be Windows for the directory and UNC share paths to make sense.
   */
  readonly platform: ServerPlatform;
  readonly criticality:
    | "low"
    | "moderate"
    | "high"
    | "severe";
}

/** Infrastructure every mid-size enterprise plausibly runs. */
export const SERVER_PROFILES: readonly ServerProfile[] =
  [
    {
      hostname: "dc-01",
      role: "Domain Controller",
      platform: "windows",
      criticality: "severe",
    },
    {
      hostname: "dc-02",
      role: "Domain Controller",
      platform: "windows",
      criticality: "severe",
    },
    {
      hostname: "fs-01",
      role: "File Server",
      platform: "windows",
      criticality: "high",
    },
    {
      hostname: "sql-01",
      role: "Database Server",
      platform: "any",
      criticality: "severe",
    },
    {
      hostname: "app-01",
      role: "Application Server",
      platform: "any",
      criticality: "high",
    },
    {
      hostname: "web-01",
      role: "Web Server",
      platform: "any",
      criticality: "moderate",
    },
    {
      hostname: "bkp-01",
      role: "Backup Server",
      platform: "any",
      criticality: "high",
    },
    {
      hostname: "jump-01",
      role: "Jump Host",
      platform: "linux",
      criticality: "severe",
    },
  ];

export interface ApplicationProfile {
  readonly name: string;
  readonly kind:
    | "siem"
    | "edr"
    | "identity"
    | "email"
    | "hr"
    | "cloud"
    | "file_server"
    | "custom";
  /** Whether ordinary staff authenticate against it day to day. */
  readonly staffFacing: boolean;
}

export const APPLICATION_PROFILES: readonly ApplicationProfile[] =
  [
    {
      name: "Identity Provider",
      kind: "identity",
      staffFacing: true,
    },
    {
      name: "Endpoint Defense",
      kind: "edr",
      staffFacing: false,
    },
    {
      name: "Security Analytics",
      kind: "siem",
      staffFacing: false,
    },
    {
      name: "Corporate Mail",
      kind: "email",
      staffFacing: true,
    },
    {
      name: "People Portal",
      kind: "hr",
      staffFacing: true,
    },
    {
      name: "Cloud Platform",
      kind: "cloud",
      staffFacing: false,
    },
    {
      name: "Document Store",
      kind: "file_server",
      staffFacing: true,
    },
    {
      name: "Expense System",
      kind: "custom",
      staffFacing: true,
    },
    {
      name: "Code Platform",
      kind: "custom",
      staffFacing: false,
    },
    {
      name: "Customer CRM",
      kind: "custom",
      staffFacing: true,
    },
  ];

export interface FileProfile {
  readonly name: string;
  readonly directory: string;
  readonly classification:
    | "public"
    | "internal"
    | "confidential"
    | "restricted";
  /** Departments the document plausibly belongs to. */
  readonly departments: readonly string[];
}

export const FILE_PROFILES: readonly FileProfile[] =
  [
    {
      name: "quarterly-forecast.xlsx",
      directory: "Finance/Reporting",
      classification: "confidential",
      departments: ["Finance", "Executive"],
    },
    {
      name: "payroll-export.csv",
      directory: "Finance/Payroll",
      classification: "restricted",
      departments: ["Finance", "Human Resources"],
    },
    {
      name: "vendor-payments.xlsx",
      directory: "Finance/AP",
      classification: "confidential",
      departments: ["Finance"],
    },
    {
      name: "employee-records.xlsx",
      directory: "HR/Records",
      classification: "restricted",
      departments: ["Human Resources"],
    },
    {
      name: "compensation-bands.xlsx",
      directory: "HR/Compensation",
      classification: "restricted",
      departments: ["Human Resources", "Executive"],
    },
    {
      name: "network-diagram.vsdx",
      directory: "IT/Documentation",
      classification: "internal",
      departments: ["Information Technology"],
    },
    {
      name: "service-accounts.kdbx",
      directory: "IT/Credentials",
      classification: "restricted",
      departments: ["Information Technology"],
    },
    {
      name: "incident-runbook.docx",
      directory: "Security/Runbooks",
      classification: "internal",
      departments: ["Security"],
    },
    {
      name: "detection-coverage.xlsx",
      directory: "Security/Engineering",
      classification: "internal",
      departments: ["Security"],
    },
    {
      name: "architecture-overview.pdf",
      directory: "Engineering/Docs",
      classification: "internal",
      departments: ["Engineering"],
    },
    {
      name: "deployment-keys.txt",
      directory: "Engineering/Ops",
      classification: "restricted",
      departments: ["Engineering", "Information Technology"],
    },
    {
      name: "pipeline-forecast.xlsx",
      directory: "Sales/Planning",
      classification: "confidential",
      departments: ["Sales"],
    },
    {
      name: "customer-list.csv",
      directory: "Sales/Accounts",
      classification: "confidential",
      departments: ["Sales", "Marketing"],
    },
    {
      name: "campaign-brief.docx",
      directory: "Marketing/Campaigns",
      classification: "internal",
      departments: ["Marketing"],
    },
    {
      name: "brand-guidelines.pdf",
      directory: "Marketing/Brand",
      classification: "public",
      departments: ["Marketing"],
    },
    {
      name: "merger-due-diligence.pdf",
      directory: "Legal/Corporate",
      classification: "restricted",
      departments: ["Legal", "Executive"],
    },
    {
      name: "supplier-contract.pdf",
      directory: "Legal/Contracts",
      classification: "confidential",
      departments: ["Legal"],
    },
    {
      name: "board-minutes.docx",
      directory: "Executive/Board",
      classification: "restricted",
      departments: ["Executive"],
    },
  ];
