package srvcifIC201820;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.util.Date;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.x509.X509V3CertificateGenerator;

@SuppressWarnings( "deprecation" )
public class Seg {

	/**
	 * Clase con los metodos que proveen la seguridad del protocolo.
	 * Infraestructura Computacional. 
	 * Universidad de los Andes.
	 * Las tildes han sido eliminadas a proposito, para reducir problemas de compatibilidad.
	 * @author Michael Andres Carrillo Pinzon
	 * 
	 * Los comentarios han sido eliminados a proposito (es responsabilidad del estudiante estudiar para 
	 * entender las operaciones). 
	 */
	
	public static final String DES = "DES";
	public static final String AES = "AES";
	public static final String BLOWFISH = "Blowfish";
	public static final String RSA = "RSA";
	public static final String RC4 = "RC4";
	
	public static byte[] se (byte[] msg, Key key , String algo)
			throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, 
			NoSuchAlgorithmException, NoSuchPaddingException {
		algo = algo + 
				(algo.equals(DES) || algo.equals(AES)?"/ECB/PKCS5Padding":"");
		Cipher decifrador = Cipher.getInstance(algo); 
		decifrador.init(Cipher.ENCRYPT_MODE, key); 
		return decifrador.doFinal(msg);
	}
	
	public static byte[] sd (byte[] msg, Key key , String algo)
			throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, 
			NoSuchAlgorithmException, NoSuchPaddingException {
		algo = algo + 
				(algo.equals(DES) || algo.equals(AES)?"/ECB/PKCS5Padding":"");
		Cipher decifrador = Cipher.getInstance(algo); 
		decifrador.init(Cipher.DECRYPT_MODE, key); 
		return decifrador.doFinal(msg);
	}
	
	public static byte[] ae (byte[] msg, Key key , String algo) 
			throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, 
			NoSuchAlgorithmException, NoSuchPaddingException {
		Cipher decifrador = Cipher.getInstance(algo); 
		decifrador.init(Cipher.ENCRYPT_MODE, key); 
		return decifrador.doFinal(msg);
	}
	
	public static byte[] ad (byte[] msg, Key key , String algo) 
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, 
			IllegalBlockSizeException, BadPaddingException {
		Cipher decifrador = Cipher.getInstance(algo); 
		decifrador.init(Cipher.DECRYPT_MODE, key); 
		return decifrador.doFinal(msg);
	}

	public static byte[] hdg (byte[] msg, Key key, String algo) throws NoSuchAlgorithmException,
			InvalidKeyException, IllegalStateException, UnsupportedEncodingException {
		Mac mac = Mac.getInstance(algo);
		mac.init(key);

		byte[] bytes = mac.doFinal(msg);
		return bytes;
	}
	
	public static boolean vi(byte[] msg, Key key, String algo, byte [] hash ) throws Exception
	{
		byte [] nuevo = hdg(msg, key, algo);
		if (nuevo.length != hash.length) {
			return false;
		}
		for (int i = 0; i < nuevo.length ; i++) {
			if (nuevo[i] != hash[i]) return false;
		}
		return true;
	}

	public static SecretKey kgg(String algoritmo) 
			throws NoSuchAlgorithmException, NoSuchProviderException	{
		int tamLlave = 0;
		if (algoritmo.equals(DES))
			tamLlave = 64;
		else if (algoritmo.equals(AES))
			tamLlave = 128;
		else if (algoritmo.equals(BLOWFISH))
			tamLlave = 128;
		else if (algoritmo.equals(RC4))
			tamLlave = 128;
		
		if (tamLlave == 0) throw new NoSuchAlgorithmException();
		
		KeyGenerator keyGen;
		SecretKey key;
		keyGen = KeyGenerator.getInstance(algoritmo,"BC");
		keyGen.init(tamLlave);
		key = keyGen.generateKey();
		return key;
	}

	public static java.security.cert.X509Certificate gc(KeyPair pair) throws InvalidKeyException,
	NoSuchProviderException, SignatureException, IllegalStateException, NoSuchAlgorithmException, CertificateException {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

		X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
		certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
		certGen.setIssuerDN(new X500Principal("CN=Test Certificate"));
		certGen.setNotBefore(new Date(System.currentTimeMillis() - 10000000));
		certGen.setNotAfter(new Date(System.currentTimeMillis() + 10000000));
		certGen.setSubjectDN(new X500Principal("CN=Test Certificate"));
		certGen.setPublicKey(pair.getPublic());
		certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");

		certGen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
		certGen.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.digitalSignature| KeyUsage.keyEncipherment));
		certGen.addExtension(X509Extensions.ExtendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));

		certGen.addExtension(X509Extensions.SubjectAlternativeName, false, new GeneralNames(
				new GeneralName(GeneralName.rfc822Name, "test@test.test")));
		return certGen.generate(pair.getPrivate(), "BC") ;
	}

	public static KeyPair grsa() throws NoSuchAlgorithmException {
		KeyPairGenerator kpGen = KeyPairGenerator.getInstance(RSA);
		kpGen.initialize(1024, new SecureRandom());
		return kpGen.generateKeyPair();
	}	

	
}
