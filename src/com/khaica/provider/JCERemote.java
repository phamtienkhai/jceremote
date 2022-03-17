package com.khaica.provider;

import java.security.AccessController;
import java.security.Provider;

public final class JCERemote extends Provider {

	public JCERemote() {
		super("JCERemote", 1.0, "JCE Remote 1.0");
		AccessController.doPrivileged(new java.security.PrivilegedAction() {
			public Object run() {
				put("Signature.SHA1withRSA", "com.khaica.provider.jceremote.JCERemoteSignature$SHA1withRSA");
				put("Signature.SHA256withRSA", "com.khaica.provider.jceremote.JCERemoteSignature$SHA256withRSA");
				return null;
			}
		});
	}

	public JCERemote(String name, double version, String info) {
		super(name, version, info);

	}

	/**
	 * 
	 */
	private static final long serialVersionUID = 3144298330525797659L;

}
