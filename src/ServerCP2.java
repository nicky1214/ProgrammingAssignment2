import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class ServerCP2 {

    public static void main(String[] args) {

        boolean authenticated = false;
        int port = 4321;
        if (args.length > 0) port = Integer.parseInt(args[0]);

        ServerSocket welcomeSocket = null;
        Socket connectionSocket = null;
        DataOutputStream toClient = null;
        DataInputStream fromClient = null;

        FileOutputStream fileOutputStream = null;
        BufferedOutputStream bufferedFileOutputStream = null;
        PrivateKey APKey = null;
        Cipher decryptCipher = null;
        try {
            welcomeSocket = new ServerSocket(port);
            connectionSocket = welcomeSocket.accept();

            fromClient = new DataInputStream(connectionSocket.getInputStream());
            toClient = new DataOutputStream(connectionSocket.getOutputStream());

            InputStream fis = new FileInputStream("cheowfu.crt");
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate serverCert = (X509Certificate) cf.generateCertificate(fis);
            PrivateKey privateKey = com.example.csepa2.PrivateKeyReader.get("private_key.der");
            Cipher ecipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            ecipher.init(Cipher.ENCRYPT_MODE, privateKey);

            while (!connectionSocket.isClosed()) {
                if (!authenticated){

                    //Receiving nonce
                    int nonce_length = fromClient.readInt();
                    byte[] nonce = new byte[nonce_length];
                    fromClient.readFully(nonce, 0, nonce_length);
                    System.out.println("Nonce received...");

                    //encrypt nonce
                    System.out.println("Encrypting nonce...");
                    byte[] encryptedNonce = ecipher.doFinal(nonce);

                    //send encrypted nonce to client
                    System.out.println("Sending encrypted nonce to client...");
                    toClient.writeInt(encryptedNonce.length);
                    toClient.write(encryptedNonce);
                    toClient.flush();

                    //receiving certification request from client
                    String Msg = fromClient.readUTF();
                    System.out.println("Request from Client: " + Msg);
                    while (true) {
                        if (Msg.equals("Give me your certificate signed by CA")) {
                            System.out.println("sending certificate to client..");
                            toClient.write(serverCert.getEncoded());
                            toClient.flush();
                            break;
                        } else {
                            connectionSocket.close();
                            System.out.println("Socket closed by Server");
                        }
                    }
                    authenticated = true;
                    System.out.println("Successful authentication with client :)");
                }

                //Authentication successful. File transfer begins
                int packetType = fromClient.readInt();
                // If the packet is for transferring the filename
                if (packetType == 0) {

                    System.out.println("Receiving file...");

                    int numBytes = fromClient.readInt();
                    int keynumBytes = fromClient.readInt();
                    byte [] filename = new byte[numBytes];
//                    String keytoken ="";
                    byte [] keyBytes = new byte[keynumBytes];
                    // Must use read fully!
                    // See: https://stackoverflow.com/questions/25897627/datainputstream-read-vs-datainputstream-readfully
                    fromClient.readFully(filename, 0, numBytes);
                    fromClient.readFully(keyBytes,0,keynumBytes);

                    fileOutputStream = new FileOutputStream("recvcp2"+new String(filename));
                    bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);
//                    Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
//                    String keytoken = keyBytes.toString();

                    SecretKeySpec secretKey = new SecretKeySpec(keyBytes,"AES");

                    decryptCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                    decryptCipher.init(Cipher.DECRYPT_MODE,secretKey);

                    // If the packet is for transferring a chunk of the file
                } else if (packetType == 1) {
                    System.out.println("Receiving file packets...");

                    int numBytes = fromClient.readInt();
                    int blocksize = fromClient.readInt();
                    byte [] block = new byte[blocksize];
                    fromClient.readFully(block, 0, blocksize);
                    byte[] decryptedBytes = decryptCipher.doFinal(block);

                    if (numBytes > 0)
                        bufferedFileOutputStream.write(decryptedBytes, 0, numBytes);

                    if (numBytes < 117) {
                        System.out.println("Closing connection...");

                        if (bufferedFileOutputStream != null) bufferedFileOutputStream.close();
                        if (bufferedFileOutputStream != null) fileOutputStream.close();
                        fromClient.close();
                        toClient.close();
                        connectionSocket.close();
                    }
                }

            }
        } catch (Exception e) {e.printStackTrace();}

    }

}