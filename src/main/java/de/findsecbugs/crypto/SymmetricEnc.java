
package de.findsecbugs.crypto;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class SymmetricEnc {

	public File encrypt(File file, SecretKey key) throws GeneralSecurityException, IOException {
		byte[] data = Files.readAllBytes(file.toPath());
		Files.write(file.toPath(), encrypt(data, key));
		return file;
	}

	public byte[] encrypt(byte[] data, SecretKey key) throws GeneralSecurityException {
		byte [] ivb = new byte[16];
		SecureRandom rnd = new SecureRandom();
		rnd.nextBytes(ivb);

		IvParameterSpec iv = new IvParameterSpec(ivb);

		Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
		c.init(Cipher.ENCRYPT_MODE, key, iv);

		int conv_len = 0;
		byte[] res = new byte[c.getOutputSize(data.length)];
		for (int i = 0; i + 1024 <= data.length; i += 1024) {
			byte[] input = new byte[1024]; 
			System.arraycopy(data, i, input, 0, 1024);
			conv_len += c.update(input, 0, input.length, res, i);
		}
		conv_len += c.doFinal(data, conv_len, data.length - conv_len, res, conv_len);

		byte[] ret = new  byte[res.length + ivb.length];
		System.arraycopy(ivb, 0, ret, 0, ivb.length);
		System.arraycopy(res, 0, ret, ivb.length, res.length);
		return ret;
	}

	public File decrypt(File file, SecretKey key) throws GeneralSecurityException, IOException {
		byte[] ciphertext = Files.readAllBytes(file.toPath());
		Files.write(file.toPath(), decrypt(ciphertext, key));
		return file;
	}

	public byte[] decrypt(byte[] ciphertext, SecretKey key) throws GeneralSecurityException {
		byte[] ivb = new byte[16];
		System.arraycopy(ciphertext, 0, ivb, 0, ivb.length);
		IvParameterSpec iv = new IvParameterSpec(ivb);
		byte[] data = new byte[ciphertext.length - ivb.length];
		System.arraycopy(ciphertext, ivb.length, data, 0, data.length);
		Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
		c.init(Cipher.DECRYPT_MODE, key, iv);

		int conv_len = 0;
		byte[] res = new byte[c.getOutputSize(data.length)];
		for (int i = 0; i + 1024 <= data.length; i += 1024) {
			byte[] input = new byte[1024];
			System.arraycopy(data, i, input, 0, 1024);
			conv_len += c.update(input, 0, input.length, res, i);
		}
		conv_len += c.doFinal(data, conv_len, data.length - conv_len, res, conv_len);

		return res;
	}
}
