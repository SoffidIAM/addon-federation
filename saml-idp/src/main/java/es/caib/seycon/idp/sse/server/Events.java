package es.caib.seycon.idp.sse.server;

public class Events {

	public static final String VERIFY = "https://schemas.openid.net/secevent/sse/event-type/verification";
	
	public static final String CAEP_SESSION_REVOKED = "https://schemas.openid.net/secevent/caep/event-type/session-revoked";
	public static final String CAEP_TOKEN_CLAIMS_CHANGE = "https://schemas.openid.net/secevent/caep/event-type/token-claims-change";
	public static final String CAEP_CREDENTIAL_CHANGE = "https://schemas.openid.net/secevent/caep/event-type/credential-change";
	public static final String CAEP_ASSURANCE_LEVEL_CHANGE = "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change";
	public static final String CAEP_DEVICE_COMPLIANCE_CHANGE = "https://schemas.openid.net/secevent/caep/event-type/device-compliance-change";

	public static final String RISC_ACCOUNT_CREDENTIAL_CHANGE_REQUIRED = "https://schemas.openid.net/secevent/risc/event-type/account-credential-change-required";
	public static final String RISC_ACCOUNT_PURGED = "https://schemas.openid.net/secevent/risc/event-type/account-purged";
	public static final String RISC_ACCOUND_DISABLED = "https://schemas.openid.net/secevent/risc/event-type/account-disabled";
	public static final String RISC_ACCOUNT_ENABLED = "https://schemas.openid.net/secevent/risc/event-type/account-enabled";
	public static final String RISC_IDENTIFIER_CHANGED = "https://schemas.openid.net/secevent/risc/event-type/identifier-changed";
	public static final String RISC_IDENTIFIER_RECYCLED = "https://schemas.openid.net/secevent/risc/event-type/identifier-recycled";
	public static final String RISC_CREDENTIAL_COMPROMISED = "https://schemas.openid.net/secevent/risc/event-type/credential-compromised";
	public static final String RISC_OPT_OUT = "https://schemas.openid.net/secevent/risc/event-type/opt-out";
	public static final String RISC_OPT_OUT_INITIATED = "https://schemas.openid.net/secevent/risc/event-type/opt-out-initiated";
	public static final String RISC_OPT_OUT_CANCELLED = "https://schemas.openid.net/secevent/risc/event-type/opt-out-cancelled";
	public static final String RISC_OPT_OUT_EFFECTIVE = "https://schemas.openid.net/secevent/risc/event-type/opt-out-effective";
	public static final String RISC_OPT_IN = "https://schemas.openid.net/secevent/risc/event-type/opt-in";
	public static final String RISC_RECOVERY_ACTIVATED = "https://schemas.openid.net/secevent/risc/event-type/recovery-activated";
	public static final String RISC_RECOVERY_INFORMATION_CHANGED = "https://schemas.openid.net/secevent/risc/event-type/recovery-information-changed";
}
