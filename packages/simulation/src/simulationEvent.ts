import type {
  DomainEvent,
  EntityId,
  EntityStatus,
} from "@endomorph/domain";

export type EventOf<
  TType extends string,
  TPayload,
> = DomainEvent<
  TType,
  TPayload
>;

// -----------------------------------------------------------------------------
// Authentication
// -----------------------------------------------------------------------------

export interface AuthLoginSucceededPayload {
  accountId: EntityId;
  userId: EntityId;
  deviceId?: EntityId;
  applicationId?: EntityId;
  sourceIp?: string;
}

export type AuthLoginSucceededEvent =
  EventOf<
    "AUTH_LOGIN_SUCCEEDED",
    AuthLoginSucceededPayload
  >;

export type AuthFailureReason =
  | "invalid_credentials"
  | "disabled_account"
  | "mfa_failed"
  | "unknown_account"
  | "other";

export interface AuthLoginFailedPayload {
  username: string;
  reason: AuthFailureReason;
  applicationId?: EntityId;
  deviceId?: EntityId;
  sourceIp?: string;
}

export type AuthLoginFailedEvent =
  EventOf<
    "AUTH_LOGIN_FAILED",
    AuthLoginFailedPayload
  >;

export type AuthenticationEvent =
  | AuthLoginSucceededEvent
  | AuthLoginFailedEvent;

// -----------------------------------------------------------------------------
// Identity
// -----------------------------------------------------------------------------

export interface AccountDisabledPayload {
  accountId: EntityId;
  reason?: string;
}

export type AccountDisabledEvent =
  EventOf<
    "ACCOUNT_DISABLED",
    AccountDisabledPayload
  >;

export interface AccountEnabledPayload {
  accountId: EntityId;
  reason?: string;
}

export type AccountEnabledEvent =
  EventOf<
    "ACCOUNT_ENABLED",
    AccountEnabledPayload
  >;

/**
 * A directory or cloud role added to an account.
 *
 * Accounts have always carried roles and nothing ever changed them, so
 * privilege escalation inside identity was not expressible at all -- every
 * intrusion in the library had to reach a host to get anywhere. In practice
 * this is one of the most common modern paths: an attacker with a valid
 * credential grants themselves an administrative role and never touches an
 * endpoint.
 */
export interface RoleGrantedPayload {
  accountId: EntityId;

  /** The role added, e.g. "global-administrator". */
  role: string;

  /** Application the role belongs to, when it is not the directory. */
  applicationId?: EntityId;

  reason?: string;
}

export type RoleGrantedEvent = EventOf<
  "ROLE_GRANTED",
  RoleGrantedPayload
>;

export type IdentityEvent =
  | AccountDisabledEvent
  | AccountEnabledEvent
  | RoleGrantedEvent;

// -----------------------------------------------------------------------------
// Sessions
// -----------------------------------------------------------------------------

export interface SessionStartedPayload {
  sessionId: EntityId;
  accountId: EntityId;
  deviceId?: EntityId;
  applicationId?: EntityId;
}

export type SessionStartedEvent =
  EventOf<
    "SESSION_STARTED",
    SessionStartedPayload
  >;

export interface SessionRevokedPayload {
  sessionId: EntityId;
  reason?: string;
}

export type SessionRevokedEvent =
  EventOf<
    "SESSION_REVOKED",
    SessionRevokedPayload
  >;

export type SessionEvent =
  | SessionStartedEvent
  | SessionRevokedEvent;

// -----------------------------------------------------------------------------
// Process execution
// -----------------------------------------------------------------------------

export interface ProcessStartedPayload {
  deviceId: EntityId;
  processId: string;
  image: string;
  commandLine?: string;
  parentProcessId?: string;

  /**
   * The parent's image path.
   *
   * The pid alone is only useful when the parent's own start event is in the
   * window, which for anything launched before the sensor -- explorer.exe,
   * services.exe, a scheduler -- it is not. Detection content overwhelmingly
   * keys on the path for exactly that reason.
   */
  parentImage?: string;
  accountId?: EntityId;
}

export type ProcessStartedEvent =
  EventOf<
    "PROCESS_STARTED",
    ProcessStartedPayload
  >;

export type ProcessEvent =
  ProcessStartedEvent;

// -----------------------------------------------------------------------------
// File activity
// -----------------------------------------------------------------------------

export type FileAccessOperation =
  | "read"
  | "write"
  | "create"
  | "delete"
  | "execute";

export interface FileAccessedPayload {
  fileId: EntityId;
  operation: FileAccessOperation;
  deviceId?: EntityId;
  accountId?: EntityId;
}

export type FileAccessedEvent =
  EventOf<
    "FILE_ACCESSED",
    FileAccessedPayload
  >;

export type FileEvent =
  FileAccessedEvent;

// -----------------------------------------------------------------------------
// Network activity
// -----------------------------------------------------------------------------

export type NetworkProtocol =
  | "tcp"
  | "udp"
  | "icmp";

export interface NetworkConnectionPayload {
  deviceId: EntityId;
  protocol: NetworkProtocol;
  sourceIp: string;
  destinationIp: string;
  sourcePort?: number;
  destinationPort?: number;

  /**
   * The process that opened the connection.
   *
   * Every real endpoint sensor reports this -- Sysmon event 3 carries the
   * pid and the image -- and without it the console can say a host is
   * beaconing but never say what is beaconing, which is the question a
   * responder actually has.
   *
   * It is also what separates a beacon from a keepalive. Both are a
   * long-lived process talking to one fixed address on 443 at an interval;
   * traffic shape alone cannot tell them apart, and the process can.
   *
   * Optional because network sensors off the host see the packet and not the
   * program. The generator populates it on everything it emits, benign
   * traffic included -- an attribute only the intrusion carries would give
   * the answer away.
   */
  processId?: string;
  image?: string;
}

export type NetworkConnectionEvent =
  EventOf<
    "NETWORK_CONNECTION",
    NetworkConnectionPayload
  >;

export type NetworkEvent =
  NetworkConnectionEvent;

// -----------------------------------------------------------------------------
// Endpoint activity
// -----------------------------------------------------------------------------

export interface EndpointHeartbeatPayload {
  deviceId: EntityId;
  status: EntityStatus;
  ipAddresses: string[];
}

export type EndpointHeartbeatEvent =
  EventOf<
    "ENDPOINT_HEARTBEAT",
    EndpointHeartbeatPayload
  >;

export type EndpointEvent =
  EndpointHeartbeatEvent;

// -----------------------------------------------------------------------------
// Security detections
// -----------------------------------------------------------------------------

export type AlertSeverity =
  | "informational"
  | "low"
  | "medium"
  | "high"
  | "critical";

export interface AlertCreatedPayload {
  alertId: EntityId;
  title: string;
  severity: AlertSeverity;
  applicationId?: EntityId;
  relatedEventIds: EntityId[];
  relatedEntityIds: EntityId[];
}

export type AlertCreatedEvent =
  EventOf<
    "ALERT_CREATED",
    AlertCreatedPayload
  >;

export type SecurityEvent =
  AlertCreatedEvent;

// -----------------------------------------------------------------------------
// Mail
// -----------------------------------------------------------------------------

/**
 * A message delivered to a mailbox.
 *
 * Email is where a large share of intrusions begin, and none of it was
 * expressible before: a plan that started with a phish had to open on a process
 * or a login, skipping the step a detection engineer most wants to write a rule
 * against. The payload carries what a mail-security log actually records -- who
 * it was from, the subject, a link, an attachment -- so a phishing detection can
 * be written and scored against benign mail that shares the same shape.
 */
export interface EmailReceivedPayload {
  /** The recipient's account. */
  accountId: EntityId;

  userId?: EntityId;

  /** Sender address, e.g. "billing@vendor.example". */
  senderAddress: string;

  senderDisplayName?: string;

  subject: string;

  /** True when the sender's domain is outside the organization. */
  external: boolean;

  /** A link in the body, when the message carries one. */
  url?: string;

  /** An attachment's file name, when the message carries one. */
  attachmentName?: string;

  /** The delivering mail gateway's address, when known. */
  sourceIp?: string;
}

export type EmailReceivedEvent = EventOf<
  "EMAIL_RECEIVED",
  EmailReceivedPayload
>;

export type MailEvent =
  EmailReceivedEvent;

// -----------------------------------------------------------------------------
// Cloud control plane
// -----------------------------------------------------------------------------

/**
 * A cloud / SaaS control-plane audit record.
 *
 * The identity and endpoint domains cannot express the intrusions that now
 * dominate: an OAuth application consented to, an access key minted for
 * persistence, a storage bucket enumerated and copied out -- all of it in a
 * provider's audit log, none of it touching a host. Modelled the way a real
 * audit log is: one record shape with an `action` and a `service`, so the whole
 * control plane is one event type and a detection reads the action rather than
 * the schema.
 */
export interface CloudAuditPayload {
  /** The identity the action was performed by or against. */
  accountId: EntityId;

  userId?: EntityId;

  /** The control-plane operation, e.g. "ConsentToApplication", "CreateAccessKey". */
  action: string;

  /** The provider service, e.g. "EntraID", "IAM", "Storage". */
  service: string;

  /** The resource acted on, when the action names one. */
  resource?: string;

  /** A modelled application, when the action involves one. */
  applicationId?: EntityId;

  /** The application's display name, when it is not a modelled entity. */
  appDisplayName?: string;

  sourceIp?: string;

  outcome?: "success" | "failure";
}

export type CloudAuditEvent = EventOf<
  "CLOUD_AUDIT",
  CloudAuditPayload
>;

export type CloudEvent = CloudAuditEvent;

// -----------------------------------------------------------------------------
// DNS
// -----------------------------------------------------------------------------

/**
 * A DNS resolution.
 *
 * DNS is one of the highest-signal detection surfaces and had no representation:
 * command-and-control over DNS, domain-generation-algorithm beacons, and data
 * tunnelled out through query names all live here and nowhere else in a
 * network's telemetry. Modelled as a resolver log line -- who asked, for what
 * name, of what type -- so a rule can read the query name and type the way a
 * DNS analytic does.
 */
export interface DnsQueryPayload {
  deviceId?: EntityId;

  accountId?: EntityId;

  /** The queried name, e.g. "login.microsoftonline.com". */
  queryName: string;

  /** The record type, e.g. "A", "AAAA", "TXT", "CNAME". */
  queryType: string;

  /** The resolved address, when the query returned one. */
  resolvedIp?: string;

  /** The querying host's address. */
  sourceIp?: string;
}

export type DnsQueryEvent = EventOf<
  "DNS_QUERY",
  DnsQueryPayload
>;

export type DnsEvent = DnsQueryEvent;

// -----------------------------------------------------------------------------
// Endomorph event union
// -----------------------------------------------------------------------------

export type SimulationEvent =
  | AuthenticationEvent
  | IdentityEvent
  | SessionEvent
  | ProcessEvent
  | FileEvent
  | NetworkEvent
  | EndpointEvent
  | SecurityEvent
  | MailEvent
  | CloudEvent
  | DnsEvent;

export type SimulationEventType =
  SimulationEvent["type"];
