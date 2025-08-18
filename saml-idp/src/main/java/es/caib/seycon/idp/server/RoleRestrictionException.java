package es.caib.seycon.idp.server;

public class RoleRestrictionException extends Exception {

	public RoleRestrictionException() {
		super();
	}

	public RoleRestrictionException(String arg0, Throwable arg1, boolean arg2, boolean arg3) {
		super(arg0, arg1, arg2, arg3);
	}

	public RoleRestrictionException(String arg0, Throwable arg1) {
		super(arg0, arg1);
	}

	public RoleRestrictionException(String arg0) {
		super(arg0);
	}

	public RoleRestrictionException(Throwable arg0) {
		super(arg0);
	}

}
