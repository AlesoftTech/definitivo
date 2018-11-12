package cliente;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Date;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;
import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V1CertificateGenerator;
import org.bouncycastle.x509.X509V3CertificateGenerator;

public class ClienteServ {

	private static final String HOST = "localhost";
	public static final int PUERTO = 8088;
	public static final String SEPARADOR = ":";
	private static String ALGORITMO;
	private static SecretKey llaveSimetrica;
	private static String ASIM = "RSA";
	public static String SIM;
	private static PublicKey pkserv;
	public static String consulta;
	private static java.security.cert.X509Certificate certificado;

	public static java.security.cert.X509Certificate generarCertificado(KeyPair pair)
			throws InvalidKeyException, NoSuchProviderException, SignatureException, IllegalStateException,
			NoSuchAlgorithmException, CertificateException {

		Security.addProvider(new BouncyCastleProvider());
		X509V3CertificateGenerator certificado = new X509V3CertificateGenerator();
		certificado.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));

		certificado.setIssuerDN(new X500Principal("CN=Test Certificate"));
		certificado.setNotBefore(new Date(System.currentTimeMillis() - 2000000000));

		certificado.setNotAfter(new Date(System.currentTimeMillis() + 20000000L));
		certificado.setSubjectDN(new X500Principal("CN=Test Certificate"));
		certificado.setPublicKey(pair.getPublic());
		certificado.setSignatureAlgorithm("SHA256WithRSAEncryption");

		certificado.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
		certificado.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(160));
		certificado.addExtension(X509Extensions.ExtendedKeyUsage, true,
				new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));

		certificado.addExtension(X509Extensions.SubjectAlternativeName, false,
				new GeneralNames(new GeneralName(1, "test@test.test")));

		return certificado.generate(pair.getPrivate(), "BC");
	}

	public static void main(String[] args) throws Exception {

		KeyPair keyPair;
		KeyPairGenerator generator;
		generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(1024);
		keyPair = generator.generateKeyPair();

		Socket sock = null;
		PrintWriter escritor = null;
		BufferedReader lector = null;
		try {
			sock = new Socket(HOST, PUERTO);
			escritor = new PrintWriter(sock.getOutputStream(), true);
			lector = new BufferedReader(new InputStreamReader(sock.getInputStream()));
		} catch (Exception e) {
			System.err.println("Exception: " + e.getMessage());
			System.exit(1);
		}
		BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
		String fromServer;
		String fromUser;
		System.out.println("Inicio de la comunicación:");
		int estado = 0;
		while (estado < 7) {
			switch (estado) {
			case 0: // iniciar sesion
				fromUser = stdIn.readLine();
				if (fromUser.equals("HOLA")) {
					escritor.println(fromUser);
				} else if (!fromUser.equals("HOLA")) {
					System.out.println("ERROR, esperaba HOLA");
				}
				if ((fromServer = lector.readLine()).equals("OK")) {
					System.out.println("Servidor: " + fromServer);
					estado++;
				}
				break;
			case 1: // mandar algoritmos

				System.out.println("Elija un algoritmo simétrico: AES, Blowfish");
				fromUser = stdIn.readLine();
				String sim = fromUser;
				SIM = sim;

				System.out.println("Algoritmo asimétrico: RSA");
				String asim = "RSA";
				ASIM = asim;

				System.out.println("Elija un algoritmo de Hash: HMACMD5, HMACSHA1, HMACSHA256");
				fromUser = stdIn.readLine();
				String jash = fromUser;
				ALGORITMO = jash;
				String algoritmos = "ALGORITMOS" + SEPARADOR + sim + SEPARADOR + asim + SEPARADOR + jash;
				escritor.println(algoritmos);
				if ((fromServer = lector.readLine()).equals("OK")) {
					System.out.println("Servidor: " + fromServer);
					estado++;
				}
				break;
			case 2: // mandar certificado

				try {
					CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
					certificado = generarCertificado(keyPair);
					byte[] certificadoEnBytes;
					certificadoEnBytes = certificado.getEncoded();
					String certificadoEnString = DatatypeConverter.printHexBinary(certificadoEnBytes);
					escritor.println(certificadoEnString);
					System.out.println("Certificado enviado: " + certificadoEnString);

					System.out.println("Servidor: " + lector.readLine());
					String certServidor = lector.readLine();

					System.out.println("Certificado enviado por el servidor: " + certServidor);

					byte[] clearText = DatatypeConverter.parseHexBinary(certServidor);
					InputStream in = new ByteArrayInputStream(clearText);
					java.security.cert.X509Certificate certificadoS = (java.security.cert.X509Certificate) certFactory
							.generateCertificate(in);

					pkserv = certificadoS.getPublicKey();

					estado++;
					break;
				} catch (Exception e) {
					e.printStackTrace();
				}
				break;
			case 3:
				escritor.println("OK");
				// Recibir la llave simetrica
				System.out.println("Cliente: OK");
				String hexadecimal = lector.readLine();
				System.out.println("Llave simétrica cifrada: " + hexadecimal);

				Cipher cip = Cipher.getInstance(ASIM);
				cip.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
				byte[] aDescifrar = DatatypeConverter.parseHexBinary(hexadecimal);
				byte[] descifrado = cip.doFinal(aDescifrar);
				llaveSimetrica = new SecretKeySpec(descifrado, SIM);
				String cipheredText = DatatypeConverter.printHexBinary(descifrado);
				System.out.println("Llave simetrica descifrada en Hexa: " + cipheredText);

				// enviar la misma llave ?

				estado++;
				break;
			case 4:

				Cipher cip2 = Cipher.getInstance(ASIM);
				cip2.init(Cipher.ENCRYPT_MODE, pkserv);
				byte[] aConvertir = cip2.doFinal(llaveSimetrica.getEncoded());
				String temp = DatatypeConverter.printHexBinary(aConvertir);
				escritor.println(temp);
				System.out.println("Llave encriptada mandada: " + temp);
				

				String respser = lector.readLine();
				System.out.println("Servidor: " + respser);

				estado++;
				break;
			case 5: // enviar consulta
				System.out.println("Escriba la consulta a realizar: ");
				consulta = stdIn.readLine();
				
				Cipher cip3 = Cipher.getInstance(SIM);
				cip3.init(Cipher.ENCRYPT_MODE, llaveSimetrica);
				byte[] aConvertir2 = cip3.doFinal(consulta.getBytes());
				String temp2 = DatatypeConverter.printHexBinary(aConvertir2);
				escritor.println(temp2);
				System.out.println("Consulta encriptada: " + temp2);
				
				estado++;
				break;
			case 6: // generar hash de la consulta
				Mac verificador = Mac.getInstance(ALGORITMO);
				verificador.init(llaveSimetrica);
				byte[] hashPos = verificador.doFinal(consulta.getBytes());
				
				String hashHexa = DatatypeConverter.printHexBinary(hashPos);
				escritor.println(hashHexa);
				System.out.println("Hash consulta: " + hashHexa);
				

				System.out.println("Respuesta servidor: " + lector.readLine());
				estado++;
				break;
			default:
				break;
			}

		}

		escritor.close();
		lector.close();
		// cierre el socket y la entrada estándar
		stdIn.close();
		sock.close();

	}

}
