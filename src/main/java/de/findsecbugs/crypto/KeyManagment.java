
package de.findsecbugs.crypto;

import java.security.GeneralSecurityException;
import java.security.Key;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class KeyManagment {
	private final String salt = "abcdefghijklmnopqrstuvwxyz";
	
	public SecretKey getKey(char[] pwd) throws GeneralSecurityException {
		
		byte[] salt = new byte[16];
		System.arraycopy(this.salt.getBytes(), 0, salt, 0, 16);

		PBEKeySpec spec = new PBEKeySpec(pwd, salt, 6536, 128); 
		SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		Key tmpKey = skf.generateSecret(spec);
		SecretKeySpec ret = new SecretKeySpec(tmpKey.getEncoded(), "AES");
		spec.clearPassword();
		return ret;
	}	
}
