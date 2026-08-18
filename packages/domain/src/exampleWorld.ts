import type {
  Account,
  Application,
  Device,
  DomainEvent,
  FileEntity,
  Organization,
  Session,
  User,
} from "./index";

export const exampleOrganization: Organization = {
  id: "org-acme",
  name: "Acme Financial",
  status: "active",
  departments: [
    "Finance",
    "Human Resources",
    "Information Technology",
    "Security",
  ],
};

export const exampleUser: User = {
  id: "user-sarah-martinez",
  organizationId: exampleOrganization.id,
  displayName: "Sarah Martinez",
  email: "sarah.martinez@acme.test",
  department: "Finance",
  title: "Senior Financial Analyst",
  status: "active",
  accountIds: ["account-smartinez"],
  deviceIds: ["device-fin-lt-04"],
};

export const exampleAccount: Account = {
  id: "account-smartinez",
  organizationId: exampleOrganization.id,
  userId: exampleUser.id,
  username: "smartinez",
  provider: "Acme Identity",
  status: "active",
  roles: ["finance-user"],
};

export const exampleDevice: Device = {
  id: "device-fin-lt-04",
  organizationId: exampleOrganization.id,
  hostname: "FIN-LT-04",
  operatingSystem: "Windows 11",
  status: "active",
  ownerUserId: exampleUser.id,
  ipAddresses: ["10.20.30.44"],
};

export const exampleFile: FileEntity = {
  id: "file-q4-forecast",
  organizationId: exampleOrganization.id,
  name: "Q4-Forecast.xlsx",
  path: "C:\\Finance\\Q4-Forecast.xlsx",
  classification: "confidential",
  ownerUserId: exampleUser.id,
  deviceId: exampleDevice.id,
};

export const exampleApplication: Application = {
  id: "app-identity",
  organizationId: exampleOrganization.id,
  name: "Acme Identity",
  kind: "identity",
  status: "active",
};

export const exampleSession: Session = {
  id: "session-smartinez-001",
  accountId: exampleAccount.id,
  deviceId: exampleDevice.id,
  applicationId: exampleApplication.id,
  startedAt: "2026-08-18T09:14:00Z",
  status: "active",
};

export const exampleLoginEvent: DomainEvent<
  "AUTH_LOGIN",
  {
    accountId: string;
    deviceId: string;
    applicationId: string;
    successful: boolean;
  }
> = {
  id: "event-auth-login-001",
  type: "AUTH_LOGIN",
  timestamp: "2026-08-18T09:14:00Z",
  source: "identity",
  actorId: exampleAccount.id,
  subjectId: exampleUser.id,
  payload: {
    accountId: exampleAccount.id,
    deviceId: exampleDevice.id,
    applicationId: exampleApplication.id,
    successful: true,
  },
};