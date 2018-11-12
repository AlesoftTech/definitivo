package srvIC201820;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.Random;


public class Delegado4 extends Thread {
	// Constantes
	public static final String OK = "OK";
	public static final String ALGORITMOS = "ALGORITMOS";
	public static final String DES = "DES";
	public static final String AES = "AES";
	public static final String BLOWFISH = "Blowfish";
	public static final String RSA = "RSA";
	public static final String RC4 = "RC4";
	public static final String HMACMD5 = "HMACMD5";
	public static final String HMACSHA1 = "HMACSHA1";
	public static final String HMACSHA256 = "HMACSHA256";
	public static final String CERTSRV = "CERTSRV";
	public static final String CERCLNT = "CERCLNT";
	public static final String SEPARADOR = ":";
	public static final String HOLA = "HOLA";
	public static final String INICIO = "INICIO";
	public static final String ERROR = "ERROR";
	public static final String REC = "recibio-";
	// Atributos
	private Socket sc = null;
	private String dlg;
	
	Delegado4 (Socket csP, int idP) {
		sc = csP;
		dlg = new String("delegado " + idP + ": ");
	}
	
	public void run() {
		String linea;
	    System.out.println(dlg + "Empezando atencion.");
	        try {
				PrintWriter ac = new PrintWriter(sc.getOutputStream() , true);
				BufferedReader dc = new BufferedReader(new InputStreamReader(sc.getInputStream()));

				/***** Fase 1: Inicio *****/
				linea = dc.readLine();
				if (!linea.equals(HOLA)) {
					ac.println(ERROR);
				    sc.close();
					throw new Exception(dlg + ERROR + REC + linea +"-terminando.");
				} else {
					ac.println(OK);
					System.out.println(dlg + REC + linea + "-OK, continuando.");
				}
				
				/***** Fase 2: Algoritmos *****/
				linea = dc.readLine();
				if (!(linea.contains(SEPARADOR) && linea.split(SEPARADOR)[0].equals(ALGORITMOS))) {
					ac.println(ERROR);
					sc.close();
					throw new Exception(dlg + ERROR + REC + linea +"-terminando.");
				}
				
				String[] algoritmos = linea.split(SEPARADOR);
				if (!algoritmos[1].equals(DES) && !algoritmos[1].equals(AES) &&
					!algoritmos[1].equals(BLOWFISH) && !algoritmos[1].equals(RC4)){
					ac.println(ERROR);
					sc.close();
					throw new Exception(dlg + ERROR + "Alg.Simetrico" + REC + algoritmos + "-terminando.");
				}
				if (!algoritmos[2].equals(RSA)) {
					ac.println(ERROR);
					sc.close();
					throw new Exception(dlg + ERROR + "Alg.Asimetrico." + REC + algoritmos + "-terminando.");
				}
				if (!(algoritmos[3].equals(HMACMD5) || algoritmos[3].equals(HMACSHA1) ||
					  algoritmos[3].equals(HMACSHA256))) {
					ac.println(ERROR);
					sc.close();
					throw new Exception(dlg + ERROR + "AlgHash." + REC + algoritmos + "-terminando.");
				}
				System.out.println(dlg + REC + linea + "-OK, continuando.");
				ac.println(OK);

				/***** Fase 3: Recibe certificado del cliente *****/				
				String strCertificadoCliente = dc.readLine();	
				System.out.println(dlg + strCertificadoCliente + " recibio certificado del cliente. -OK, continuando.");
				ac.println(OK);
				
				/***** Fase 4: Envia certificado del servidor *****/
				ac.println("CERTSRV");
				System.out.println(dlg + "envio certificado del servidor. continuando.");				
				linea = dc.readLine();
				if (!(linea.equals(OK))) {
					ac.println(ERROR);
					throw new Exception(dlg + ERROR + REC + linea + "-terminando.");
				}
				System.out.println(dlg + "recibio-" + linea + "-OK, continuando.");

				/***** Fase 5: Envia llave simetrica *****/
				ac.println("LS");
				System.out.println(dlg + "envio llave simetrica al cliente. -OK, continuando.");
				
				/***** Fase 6: Confirma llave simetrica *****/
				linea = dc.readLine();
				if (!linea.equals("LS")) {
					ac.println(ERROR);
					throw new Exception(dlg + ERROR + "Problema confirmando llave. terminando.");
				}
				ac.println(OK);
				System.out.println(dlg + "confirmo llave simetrica. -OK, continuando.");
				
				/***** Fase 7: Lectura de la consulta *****/
				String linea1 = dc.readLine();		
				String linea2 = dc.readLine();
				System.out.println(dlg + linea1 + "," + linea2 +  " leyo consulta. -OK, continuando.");
				boolean rta = esta(linea1);
				if (rta) 
					ac.println(OK + ":DEBE");
				else 
					ac.println(OK + ":PAZYSALVO");
				
		        sc.close();
		        System.out.println(dlg + "Termino exitosamente.");
				
	        } catch (Exception e) {
	          e.printStackTrace();
	        }
	}
	
	private boolean esta(String inDato) {
		int num = Integer.parseInt(inDato);
		Random rand = new Random(); 
		int value = rand.nextInt(10);
		while (value==0)
		    value=rand.nextInt();
		return ((num - value)%2)==1;
	}
	
}
