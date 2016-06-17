package Server;

import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.sql.SQLException;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Base64.Encoder;
import java.util.Date;
import java.util.StringTokenizer;

import org.bouncycastle.operator.OperatorCreationException;

import CerificatesAndKeys.KeysAndCertificates_short;
import CerificatesAndKeys.MyMain;
//import sun.misc.BASE64Encoder;

public class Server2 {

	boolean certificateVerification = false;

	public static void main(String args[]) {

		int port = 6666;
		Server2 server = new Server2(port);
		server.startServer();
	}

	// declare a server socket and a client socket for the server;
	// declare the number of connections

	ServerSocket echoServer = null;
	Socket clientSocket = null;
	int numConnections = 0;
	int port;

	public Server2(int port) {
		this.port = port;
	}

	public void stopServer() {
		System.out.println("Server cleaning up.");
		System.exit(0);
	}

	public void startServer() {

		try {
			echoServer = new ServerSocket(port);
		} catch (IOException e) {
			System.out.println(e);
		}

		System.out.println("Server is started and is waiting for connections.");

		// When connection is received, start a new thread to process the
		// connection and wait for the next connection.

		while (true) {
			try {
				clientSocket = echoServer.accept();
				numConnections++;
				Server2Connection oneconnection = new Server2Connection(clientSocket, numConnections, this);
				new Thread(oneconnection).start();
			} catch (IOException e) {
				System.out.println(e);
			}
		}
	}

}

class Server2Connection implements Runnable {
	BufferedReader is;
	PrintStream os;
	Socket clientSocket;
	int id;
	Server2 server;
	///
	DataInputStream in;
	DataOutputStream out;
	Date date = new Date();

	public Server2Connection(Socket clientSocket, int id, Server2 server) {
		this.clientSocket = clientSocket;
		this.id = id;
		this.server = server;
		System.out.println("Connection " + id + " established with: " + clientSocket + "at" + date);
		try {

			InputStream sin = clientSocket.getInputStream(); // input socket
																// stream
			OutputStream sout = clientSocket.getOutputStream();// output socket
																// stream
			in = new DataInputStream(sin);
			out = new DataOutputStream(sout);

			// is = new BufferedReader(new
			// InputStreamReader(clientSocket.getInputStream()));
			// os = new PrintStream(clientSocket.getOutputStream());
		} catch (IOException e) {
			System.out.println(e);
		}
	}

	public void run() {
		// File passwordBase = new
		// File("C:/CommunicationTest/CA/passwordBase.txt");

		Path path = null;

		boolean done = false;
		String line = null;
		while (done != true) {
			try {
				line = in.readUTF(); // waiting for text
				System.out.println("Client " + id + ": " + line);
				if (line.startsWith(".q")) {
					done = true;
					out.writeUTF(line); // sending echo
					out.flush(); // waiting for the end of transmission
				} else if (line.startsWith(".CV")) {
					boolean certIsInTheDB = false;
					int i = 0;
					StringTokenizer st = new StringTokenizer(line, ">>>");
					// ArrayList<String> list = new ArrayList<String>();
					String[] strArray = new String[st.countTokens()];
					for (i = 0; i < strArray.length; i++) {
						strArray[i] = st.nextToken();
					}

					switch (i) {
					case 2:
						// boolean certificateVerification = false;

						// boolean certValidity = false;

						String certColumn = "";

						// rebuild received certificate
						X509Certificate receivedCert = null;// =
															// certificateFromText(strArray[2]);//stringcert2);

						// String clientName =
						// receivedCert.getSubjectDN().toString();
						try {
							receivedCert = KeysAndCertificates_short.certificateFromText(strArray[1]);// stringcert2);

						} catch (Exception e) {
							// TODO: handle exception
							out.writeUTF("bad certificate"); // sending echo
							out.flush(); // waiting for the end of transmission
							break;
						}

						// X509Certificate receivedCert =
						// certificateFromText(strArray[1]);
						// String clientName =
						// receivedCert.getSubjectDN().toString();

						System.out.println();
						// Zavisimost certificate EC ili RSA
						switch (receivedCert.getPublicKey().getAlgorithm()) {
						case "EC":
							// String columnToCheck = "";
							// columnToCheck = MySQL.column4;
							certColumn = MySQL.column3;
							System.out.println("EC certificate verification started");
							// Check if the certificate is in the DB

							System.out.println("+++++++++++++++++++++++++++++++++");
							// System.out.println(strArray[1]);
							System.out.println("Length received = " + strArray[1].length());
							System.out.println("+++++++++++++++++++++++++++++++++");

							if (MySQL.checkCell(Server.MySQL.table, certColumn, strArray[1]).equals("1")) {
								certIsInTheDB = true;
							} else {
								certIsInTheDB = false;
							}

							break;
						case "RSA":
							// columnToCheck = MySQL.column6;
							certColumn = MySQL.column5;
							System.out.println("RSA certificate verification started");
							// Check if the certificate is in the DB
							if (MySQL.checkCell(Server.MySQL.table, certColumn, strArray[1]).equals("1")) {
								certIsInTheDB = true;
							} else {
								certIsInTheDB = false;
							}

							break;
						}
						// look for presence of the certificate in the table
						// check Validity
						/*
						 * if (certIsInTheDB == true){ //get value of Validity
						 * column and compare with current date String Validity
						 * = Server.MySQL.readDB(Server.MySQL.table,
						 * columnToCheck, certColumn, strArray[1]);
						 * System.out.println("Validity = " + Validity); //if
						 * validity < curent time set true Date dateNow = new
						 * Date(); System.out.println("DateNow = " + dateNow);
						 * SimpleDateFormat sdformat = new SimpleDateFormat(
						 * "yyyy:MM:dd HH:mm:ss.ms"); Date certDate =
						 * sdformat.parse(Validity); System.out.println(
						 * "DateCert = " + certDate);
						 * 
						 * }
						 */
						if (certIsInTheDB == true) {// & (certValidity ==
													// true)){
							// certificateVerification = true;
							System.out.println("certificateVerification = TRUE");
							out.writeUTF("CV_true");
							out.flush();
						} else {
							// certificateVerification = false;
							System.out.println("certificateVerification = FALSE");
							out.writeUTF("CV_false: " + "certificate in DB -> [" + certIsInTheDB + "]");// ,
																										// Validity
																										// ->["
																										// +
																										// certValidity
																										// +
																										// "]");
							out.flush();
						}
						break;

					default:
						out.writeUTF("Command doesn't supported"); // sending
																	// echo
						out.flush(); // waiting for the end of transmission
						break;
					}

				} else if (line.startsWith(".EXIT")) {
					out.writeUTF(".q"); // sending echo
					out.flush(); 		// waiting for the end of transmission
					done = true;

				} else if (line.startsWith(".SR")) {
					int i = 0;
					StringTokenizer st = new StringTokenizer(line, ">>>");
					// ArrayList<String> list = new ArrayList<String>();
					String[] strArray = new String[st.countTokens()];
					for (i = 0; i < strArray.length; i++) {
						strArray[i] = st.nextToken();
					}
					System.out.println("point1");

					switch (i) {
					case 3:
						// rebuild user's certificate
						X509Certificate receivedCert = null;// =
															// certificateFromText(strArray[2]);//stringcert2);
						String clientName = "";
						// String clientName =
						// receivedCert.getSubjectDN().toString();

						try {
							receivedCert = KeysAndCertificates_short.certificateFromText(strArray[2]);// stringcert2);
							clientName = receivedCert.getSubjectDN().toString();

						} catch (Exception e) {
							// TODO: handle exception
							out.writeUTF("bad certificate"); // sending echo
							out.flush(); // waiting for the end of transmission
							break;
						}

						System.out.println();
						System.out.println("DEBUG: " + receivedCert);
						System.out.println("point2");
						System.out.println("point2-1" + (receivedCert.getPublicKey()).getAlgorithm());
						X509Certificate signedReceivedCert = signatureRequestHandler(tokenUser(Server.MySQL.table,
								Server.MySQL.column2, Server.MySQL.column1, clientName, strArray[1]), receivedCert);
						System.out.println("point3");
						KeysAndCertificates_short.certificateChain(signedReceivedCert, MyMain.rootCertificateEC);

						//
						System.out.println();
						byte[] clientsCertBytes = signedReceivedCert.getEncoded();
						Encoder encoder = Base64.getEncoder();
						String base64clientsCert0 = encoder.encodeToString(clientsCertBytes);
						System.out.println("Signed Certificate: " + base64clientsCert0);
						String base64clientsCert = base64clientsCert0.replaceAll("\r\n", "");
						out.writeUTF(base64clientsCert);
						out.flush(); // waiting for the end of transmission

						// Certificate's date to MySQL DATETIME format
						Date validto = receivedCert.getNotAfter();
						String validstring;
						SimpleDateFormat sdf = new SimpleDateFormat("yyyy:MM:dd HH:mm:ss");
						validstring = sdf.format(validto);

						switch ((receivedCert.getPublicKey()).getAlgorithm()) {
						case "EC":
							////
							// create temp keystore to save certificate chain
							String keystorePathString = "C:/CommunicationTest/CA/tempKeystore_"
									+ receivedCert.getSerialNumber();
							File keystorefile = new File(keystorePathString);
							path = Paths.get(keystorePathString);
							char[] password_KeyStore = "temp".toCharArray();
							String alias = "temp";

							try {
								KeysAndCertificates_short.createKeystore(keystorefile, password_KeyStore);
							} catch (KeyStoreException e1) {
								// TODO Auto-generated catch block
								e1.printStackTrace();
							} catch (NoSuchAlgorithmException e1) {
								// TODO Auto-generated catch block
								e1.printStackTrace();
							} catch (CertificateException e1) {
								// TODO Auto-generated catch block
								e1.printStackTrace();
							} catch (IOException e1) {
								// TODO Auto-generated catch block
								e1.printStackTrace();
							}

							////
							KeysAndCertificates_short.putKeyAndCertToKeystore(keystorefile, password_KeyStore, alias,
									MyMain.rootPrivateKeyEC, password_KeyStore, KeysAndCertificates_short
											.certificateChain(signedReceivedCert, MyMain.rootCertificateEC));

							X509Certificate certFromKeyStore = KeysAndCertificates_short
									.getCertificatefromKeystore(keystorefile, password_KeyStore, alias);

							byte[] clientsECCertBytes = certFromKeyStore.getEncoded();
							Encoder encoderEC = Base64.getEncoder();
							String base64clientsECCert_0 = encoderEC.encodeToString(clientsECCertBytes);
							System.out.println("Length to store 0 = " + base64clientsECCert_0.length());
							String base64clientsECCert = base64clientsECCert_0.replaceAll("\r\n", "");
							System.out.println("//////////////////////////////////////");
							System.out.println("Signed Certificate for DB: " + base64clientsECCert);
							System.out.println("Length to store = " + base64clientsECCert.length());
							System.out.println("//////////////////////////////////////");

							Server.MySQL.UpdateDB(Server.MySQL.table, Server.MySQL.column3, Server.MySQL.column1,
									base64clientsECCert, clientName);
							Server.MySQL.UpdateDB(Server.MySQL.table, Server.MySQL.column4, Server.MySQL.column1,
									validstring, clientName);
							System.out.println("EC Certificate was added to DB");
							System.out.println();
							keystorefile.deleteOnExit();
							/*
							 * / try { Files.deleteIfExists(path); } catch
							 * (NoSuchFileException x) { System.err.format(
							 * "%s: no such" + " file or directory%n", path); }
							 * catch (DirectoryNotEmptyException x) {
							 * System.err.format("%s not empty%n", path); }
							 * catch (IOException x) { // File permission
							 * problems are caught here. System.err.println(x);
							 * }
							 */
							try {
								Files.deleteIfExists(path);
							} finally {
								Files.deleteIfExists(path);
							}

							break;
						case "RSA":
							Server.MySQL.UpdateDB(Server.MySQL.table, Server.MySQL.column5, Server.MySQL.column1,
									base64clientsCert, clientName);
							Server.MySQL.UpdateDB(Server.MySQL.table, Server.MySQL.column6, Server.MySQL.column1,
									validstring, clientName);
							System.out.println("RSA Certificate was added to DB");
							System.out.println();
							break;
						}

						// Server.MySQL.readallinDB();
						// String certFromDB =
						// Server.MySQL.readDB(Server.MySQL.table,
						// Server.MySQL.column3, Server.MySQL.column1,
						// clientName);
						// System.out.println("CERTIFICATE FROM DB:");
						// System.out.println(certFromDB);
						// X509Certificate dbCert =
						// certificateFromText(certFromDB);
						break;

					default:
						out.writeUTF("bad command"); // sending echo
						out.flush(); // waiting for the end of transmission
						break;
					}
				} else {
					out.writeUTF(line); // sending echo
					out.flush(); // waiting for the end of transmission
				}
			} catch (Exception e) {
				System.out.println(e);
				done = true; // force exit if there's a problem
			}
		}

		// try {
		// if (line.startsWith(".q")) done = true;
		Date exitDate = new Date();
		System.out.println("Connection " + id + " with: " + clientSocket + " was finished at " + exitDate);
		// } catch (Exception e) { // e.g. null
		// done = true;

		// line = "[exiting]";
		// }

	}

	/*
	 * 
	 */

	public static X509Certificate signatureRequestHandler(boolean result, X509Certificate clientCertificate)
			throws OperatorCreationException, CertificateException, IOException {
		X509Certificate signedClientsCert = null;
		System.out.println("point2-2" + (clientCertificate.getPublicKey()).getAlgorithm());
		if (result) {
			switch ((clientCertificate.getPublicKey()).getAlgorithm()) {
			case "EC":
				signedClientsCert = KeysAndCertificates_short.createSignedCertificate(clientCertificate,
						MyMain.rootCertificateEC, MyMain.rootPrivateKeyEC);
				System.out.println("EC Certificate was signed");
				break;
			case "RSA":
				signedClientsCert = KeysAndCertificates_short.createSignedCertificate(clientCertificate,
						MyMain.rootCertificateRSA, MyMain.rootPrivateKeyRSA);
				System.out.println("RSA Certificate was signed");
				break;
			}
		} else {
			System.out.println("Verification failed");
		}
		return signedClientsCert;
	}

	public static boolean tokenUser(String table, String column2, String column1, String clientName, String token)
			throws IOException, SQLException {
		boolean result = false;
		if (Server.MySQL.readDB(table, column2, column1, clientName).equals(token)) {
			result = true;
			System.out.println("Verification completed");
		} else {
			System.out.println("Token doesn't match");
		}
		return result;
	}

}
