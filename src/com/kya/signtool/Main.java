// HexDump function taken from http://www.java2s.com/Code/Java/Data-Type/dumpanarrayofbytesinhexform.htm

package com.kya.signtool;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.util.Arrays;

import joptsimple.OptionParser;
import joptsimple.OptionSet;
import joptsimple.OptionSpec;

public class Main {

	private static final byte[] HEX_CHAR = new byte[] { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

	public static void main(String[] args) {
		OptionParser optParser = new OptionParser();
		OptionSpec<File> keystoreArg = optParser.acceptsAll(Arrays.asList("k", "keystore"), "Java keystore in which the key pair is").withRequiredArg().ofType(File.class);
		OptionSpec<File> signArg = optParser.acceptsAll(Arrays.asList("s", "sign"), "Action to sign the given file (or stdin)").withOptionalArg().ofType(File.class);
		OptionSpec<File> verifyArg = optParser.acceptsAll(Arrays.asList("v", "verify"), "Action to verify the given file (or stdin)").withOptionalArg().ofType(File.class);
		OptionSpec<File> signaturefileArg = optParser.acceptsAll(Arrays.asList("f", "signature-file"), "Read or write in a signature file (stdin or stdout if not specified)").withRequiredArg().ofType(File.class);
		OptionSpec<String> storetypeArg = optParser.acceptsAll(Arrays.asList("st", "storetype"), "Keystore type").withRequiredArg().ofType(String.class).defaultsTo("JKS");
		OptionSpec<String> storepassArg = optParser.acceptsAll(Arrays.asList("sp", "storepass"), "Keystore password").withRequiredArg().ofType(String.class);
		OptionSpec<String> keypassArg = optParser.acceptsAll(Arrays.asList("kp", "keypass"), "With ['s', 'sign']: Privaye key password").withRequiredArg().ofType(String.class);
		OptionSpec<String> aliasArg = optParser.acceptsAll(Arrays.asList("a", "alias"), "Key alias to use").withRequiredArg().ofType(String.class).defaultsTo("mykey");
		optParser.accepts("hex", "With ['s', 'sign']: write the signature as hexadecimal dump");
		optParser.acceptsAll(Arrays.asList("h", "help"), "This help");
		
		OptionSet optSet;
		try {
			optSet = optParser.parse(args);
			if (optSet.has("h")) {
				optParser.printHelpOn(System.out);
				System.exit(0);
				return ;
			}
			if (!optSet.has(keystoreArg))
				throw new Exception("Missing required option ['k', 'keystore']");
			if (!optSet.has(signArg) && !optSet.has(verifyArg))
				throw new Exception("Missing required option ['s', 'sign'] OR ['v', 'verify']");
			if (optSet.has(signArg) && optSet.has(verifyArg))
				throw new Exception("Options ['s', 'sign'] and ['v', 'verify'] cannot be used at the same time");
			if (optSet.has(verifyArg) && !optSet.hasArgument(verifyArg) && !optSet.has(signaturefileArg))
				throw new Exception("With ['v', 'verify'], at least ['v', 'verify'] argument or ['f', 'signature-file'] must be set (There is only one stdin)");
		}
		catch (Exception e) {
			System.out.println(e.getMessage());
			try {
				optParser.printHelpOn(System.out);
			} catch (IOException e1) {
				e1.printStackTrace();
			}
			System.exit(42);
			return ;
		}
		
		KeyStore keystore;
		FileInputStream fis = null;
		try {
			keystore = KeyStore.getInstance(optSet.valueOf(storetypeArg));

			fis = new FileInputStream(optSet.valueOf(keystoreArg));

			char[] storepass;
			if (optSet.has(storepassArg))
				storepass = optSet.valueOf(storepassArg).toCharArray();
			else
				storepass = System.console().readPassword("Keystore password: ");

			keystore.load(fis, storepass);
			
			if (!keystore.containsAlias(optSet.valueOf(aliasArg)))
				throw new Exception("Keystore does not contains alias: " + optSet.valueOf(aliasArg));
		} catch (Exception e) {
			System.err.println(e.getMessage());
			System.exit(42);
			return ;
		}
		finally {
            try {
            	if (fis != null)
					fis.close();
			}
        	catch (IOException e) {
				e.printStackTrace();
				System.exit(42);
				return ;
			}
		}

		// SIGNATURE
		if (optSet.has(signArg)) {
			char[] keypass;
			if (optSet.has(keypassArg))
				keypass = optSet.valueOf(keypassArg).toCharArray();
			else
				keypass = System.console().readPassword("Key password: ");
			
			PrivateKey key;
			InputStream fileIS;
			OutputStream signatureOS;
			try {
				key = (PrivateKey)keystore.getKey(optSet.valueOf(aliasArg), keypass);
				if (optSet.hasArgument(signArg))
					fileIS = new FileInputStream(optSet.valueOf(signArg));
				else
					fileIS = System.in;
				if (optSet.hasArgument(signaturefileArg))
					signatureOS = new FileOutputStream(optSet.valueOf(signaturefileArg));
				else
					signatureOS = System.out;
			}
			catch (Exception e) {
				System.err.println(e.getMessage());
				System.exit(42);
				return ;
			}
			
			try {
				String hexFileName = null;
				if (optSet.has("hex")) {
					hexFileName = "";
					if (optSet.hasArgument(signArg))
						hexFileName = optSet.valueOf(signArg).getAbsolutePath();
				}
				Main.Sign(key, fileIS, signatureOS, hexFileName);
			}
			finally {
				try {
					if (fileIS != null && fileIS != System.in)
						fileIS.close();
					if (signatureOS != null && signatureOS != System.out)
						signatureOS.close();
				}
	        	catch (IOException e) {
					e.printStackTrace();
					System.exit(42);
					return ;
				}
			}
		}
		
		// VERIFICATION
		else if (optSet.has(verifyArg)) {
			Certificate certificate;
			InputStream fileIS;
			InputStream signatureIS;
			try {
				certificate = keystore.getCertificate(optSet.valueOf(aliasArg));
				if (optSet.hasArgument(verifyArg))
					fileIS = new FileInputStream(optSet.valueOf(verifyArg));
				else
					fileIS = System.in;
				if (optSet.hasArgument(signaturefileArg))
					signatureIS = new FileInputStream(optSet.valueOf(signaturefileArg));
				else
					signatureIS = System.in;
			}
			catch (Exception e) {
				System.err.println(e.getMessage());
				System.exit(42);
				return ;
			}
			
			try {
				Main.Verify(certificate, fileIS, signatureIS);
			}
			finally {
				try {
					if (fileIS != null && fileIS != System.in)
						fileIS.close();
					if (signatureIS != null && signatureIS != System.in)
						signatureIS.close();
				}
	        	catch (IOException e) {
					e.printStackTrace();
					System.exit(42);
					return ;
				}
			}
		}
	}

	public static void Sign(PrivateKey key, InputStream fileIS, OutputStream signatureOS, String hexFileName) {
		try {
			Signature sign = Signature.getInstance("SHA1with" + key.getAlgorithm());
			sign.initSign(key);
			
			BufferedInputStream bis = new BufferedInputStream(fileIS);
			byte[] buffer = new byte[4096];
			int len;
			while (bis.available() > 0) {
				len = bis.read(buffer);
				sign.update(buffer, 0, len);
			}
			
			byte[] signature = sign.sign();
			if (hexFileName != null) {
				if (hexFileName.length() > 0)
					signatureOS.write((key.getAlgorithm() + "(" + hexFileName + ")= ").getBytes());
				signatureOS.write(Main.HexDump(signature).getBytes());
				signatureOS.write('\n');
			}
			else
			signatureOS.write(signature);
		}
		catch (Exception e) {
			System.err.println(e.getMessage());
			System.exit(42);
			return ;
		}
	}
	
	public static final String HexDump( byte[] buffer ) {
		if ( buffer == null )
		{
			return "";
		}

		StringBuffer sb = new StringBuffer();

		for ( int i = 0; i < buffer.length; i++ ) {
			sb.append((char)(HEX_CHAR[(buffer[i] & 0x00F0) >> 4])).append((char)(HEX_CHAR[buffer[i] & 0x000F]));
		}

		return sb.toString();
	}
	
	public static void Verify(Certificate certificate, InputStream fileIS, InputStream signatureIS) {
		try {
			Signature sign = Signature.getInstance("SHA1with" + certificate.getPublicKey().getAlgorithm());
			sign.initVerify(certificate);

			BufferedInputStream bis = new BufferedInputStream(fileIS);
			byte[] buffer = new byte[4096];
			int len;
			while (bis.available() > 0) {
				len = bis.read(buffer);
				sign.update(buffer, 0, len);
			}

			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			while (signatureIS.available() > 0) {
				len = signatureIS.read(buffer);
				baos.write(buffer, 0, len);
			}
			
			boolean success = sign.verify(baos.toByteArray());
			
			if (success) {
				System.out.println("SUCCESS");
				System.exit(0);
				return ;
			}

			System.out.println("FAILURE");
			System.exit(1);
		}
		catch (Exception e) {
			System.err.println(e.getMessage());
			System.exit(42);
			return ;
		}
	}
}
