package de.findsecbugs.crypto;

//import com.sun.istack.internal.Nullable;

import org.jetbrains.annotations.Nullable;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Scanner;
import java.util.logging.FileHandler;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

import javax.crypto.SecretKey;
import javax.swing.plaf.TextUI;

public class PasswordManager {
	private static final KeyManagment km = new KeyManagment();
	private static final SymmetricEnc symEnc = new SymmetricEnc();
	private static final String storageLocation = "passwords.txt";
	private static final Logger logger = Logger.getLogger("mngmtLogger");
	private static Scanner s;
	
	public static void main(String[] args) throws GeneralSecurityException {
		System.out.println("############################################################");
		System.out.println("");
		System.out.println("\tWelcome to your very trusty Password Manager!");
		System.out.println(""); 
		System.out.println("############################################################");
		s = new Scanner(System.in);
		try {
			FileHandler fh = new FileHandler("mngmt.log");
			fh.setFormatter(new SimpleFormatter());
			
			logger.addHandler(fh); 
			logger.setUseParentHandlers(false);
		} catch (IOException e) {
			System.out.println("Could not open log file.");
			System.exit(1);
		}
		
		
		System.out.println("What do you  want to do? (list, add) \n\t");
		String action = s.next();
		if("list".equals(action)) { 
			listPasswords();
		} else if("add".equals(action)) { 
			addPassword();
		} else {
			System.out.println("Sorry, I do not know this action (" + action + ")");
		}
		s.close();
	}
	
	private static char[] readMasterPWD() {
		System.out.print("Please specify your master password: ");
		return s.next().toCharArray();
	}
	
	private static void createPWStorage(File pwFile, SecretKey key) throws GeneralSecurityException {
		System.out.println("Creating password storage file");
		try {
			Files.write(pwFile.toPath(), "identifier;user;password\n".getBytes());
			symEnc.encrypt(pwFile, key);
			logger.info("Password storage file was created");
		} catch (IOException e) {
			logSevere("Password storage file could not be created: " + e.getCause());
//			logger.severe("Password storage file could not be created: " + e.getCause());
			System.out.println("Could not create passwort storage file!");
		}
	}
	
	private static byte[] readPWStorage() throws GeneralSecurityException {
		File pwFile = new File(storageLocation);
		
		char[] mPwd = readMasterPWD();
		SecretKey key = km.getKey(mPwd);
		Arrays.fill(mPwd, ' ');
		
		if(!pwFile.exists()) {
			createPWStorage(pwFile, key);
		}
		try {
			return symEnc.decrypt(Files.readAllBytes(pwFile.toPath()), key);
		} catch (IOException e) {
			logSevere("Password storage file could not be read: " + e.getCause());
//			logger.severe("Password storage file could not be read: " + e.getCause());
			System.out.println("Could not read password storage file!");
		}
		return null;
	}
	
	public static void addPassword() throws GeneralSecurityException {
		System.out.print("User name: ");
		String user = s.next();
		System.out.print("Password: ");
		String pwd = s.next(); 
		System.out.print("Identifier: ");
		String ident = s.next();
		
		String storage = new String(readPWStorage());
		storage += ident + ";" + user + ";" + pwd + "\n";
		
		char[] mPwd = readMasterPWD();
		SecretKey key = km.getKey(mPwd);
		Arrays.fill(mPwd, ' ');
		
		File pwFile = new File(storageLocation);
		try {
			Files.write(pwFile.toPath(), storage.getBytes());
			symEnc.encrypt(pwFile, key);
			logInfo("Added new credentials for: " + ident);
//			logger.info("Added new credentials for: " + ident);
		} catch (IOException e) {
			logSevere("Password storage file could not be written: " + e.getCause());
//			logger.severe("Password storage file could not be written: " + e.getCause());
			System.out.println("Could not write to storage file!");
		}
		
	}

	public static void listPasswords() throws GeneralSecurityException {
		byte[] storage = readPWStorage();
		logger.info("Listed passwords");
		if(storage != null) {
			System.out.println(new String(storage));
		} else {
			System.out.println("Something went wrong");
		}
	}

	private static void logSevere(String message) {
		logger.severe(sanitizeLogMessage(message));
	}

	private static void logInfo(String message) {
		logger.info(sanitizeLogMessage(message));
	}

	@Nullable
	private static String sanitizeLogMessage(@Nullable String message) {
		if (message != null) {
			return message.replaceAll("[\r\n]", "");
		} else {
			return null;
		}
	}
}
