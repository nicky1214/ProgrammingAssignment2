import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.Socket;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import javax.crypto.Cipher;


public class ClientCP1{


    public static void main(String[] args) {

        String filename = "nokia_ringtone.mp3";
        if (args.length > 0) filename = args[0];

        String serverAddress = "localhost";
        if (args.length > 1) filename = args[1];

        int port = 54321;
        if (args.length > 2) port = Integer.parseInt(args[2]);

        int numBytes = 0;

        Socket clientSocket = null;

        DataOutputStream toServer = null;
        DataInputStream fromServer = null;


        FileInputStream fileInputStream = null;
        BufferedInputStream bufferedFileInputStream = null;

        int certificatePacket = 0;

        long timeStarted = System.nanoTime();

        try {
            System.out.println("Establishing connection to server...");

            // Connect to server and get the input and output streams
            clientSocket = new Socket(serverAddress, port);
            toServer = new DataOutputStream(clientSocket.getOutputStream());
            fromServer = new DataInputStream(clientSocket.getInputStream());

            InputStream fis = new FileInputStream("cacse.crt");
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate CAcert = (X509Certificate) cf.generateCertificate(fis);

            PublicKey PubKey = CAcert.getPublicKey();
            Cipher dcipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

            //create a nonce to check that server is indeed a live server.
            byte[] nonce = new byte[32];
            SecureRandom random = new SecureRandom();
            random.nextBytes(nonce);

            //sending nonce to server
            System.out.println("Sending nonce to server..");
            toServer.writeInt(nonce.length);
            toServer.write(nonce);

            //retrieving nonce from server
            System.out.println("retrieving encrypted nonce from server..");

            //For some reason, read has stopped working properly for bytes. Must use readFully otherwise might lose bytes
            int encrypted_nonce_size = fromServer.readInt();
            byte[] encrypted_nonce = new byte[encrypted_nonce_size];
            fromServer.readFully(encrypted_nonce, 0, encrypted_nonce_size);

            //request certificate
            System.out.println("Requesting certificate from server..");
            toServer.writeUTF("Give me your certificate signed by CA");
            X509Certificate ServerCert = (X509Certificate) cf.generateCertificate(fromServer);
            PublicKey serverKey = ServerCert.getPublicKey();

            //check and validate cert
            try{
                ServerCert.checkValidity();
                ServerCert.verify(PubKey);
            }catch(Exception e){
                e.printStackTrace();
            }
            System.out.println("Cert Verified =)");

            //decrypt nonce
            dcipher.init(Cipher.DECRYPT_MODE, serverKey);
            byte[] decrypted_nonce = dcipher.doFinal(encrypted_nonce);

            //check that the decrypted nonce is the same as the originally sent nonce
            if (Arrays.equals(decrypted_nonce,nonce)){
                System.out.println("Server verified");
            }
            else{
                System.out.println("Server verification failed");
                System.out.println("Closing all connections...");
                toServer.close();
                fromServer.close();
                clientSocket.close();
            }
            System.out.println("Successful authentication with server :)");

            //authentication successful. Sending goodies now
            System.out.println("Sending file...");
            Cipher encryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            encryptCipher.init(Cipher.ENCRYPT_MODE, serverKey);

            //Send the filename and the keytoken
            toServer.writeInt(0);
            toServer.writeInt(filename.getBytes().length);
            toServer.write(filename.getBytes());

            // Open the file
            fileInputStream = new FileInputStream(filename);
            bufferedFileInputStream = new BufferedInputStream(fileInputStream);

            byte [] fromFileBuffer = new byte[117];

            // Send the encrypted file
            for (boolean fileEnded = false; !fileEnded;) {
                numBytes = bufferedFileInputStream.read(fromFileBuffer);
                fileEnded = numBytes < 117;
                byte[] encryptedBytes =  encryptCipher.doFinal(fromFileBuffer);
                int encryptedNumBytes = encryptedBytes.length;
                toServer.writeInt(1);
                toServer.writeInt(encryptedNumBytes);
                toServer.writeInt(numBytes);
                toServer.write(encryptedBytes);
                toServer.flush();
            }

            while (true){
                String end = fromServer.readUTF();
                if (end.equals("Finish reading")){
                    System.out.println("Server: " + end);
                    break;
                }
                else
                    System.out.println("End request failed...");
            }

            bufferedFileInputStream.close();
            fileInputStream.close();

            System.out.println("Closing connection...");

        } catch (Exception e) {e.printStackTrace();}

        long timeTaken = System.nanoTime() - timeStarted;
        System.out.println("Program took: " + timeTaken/1000000.0 + "ms to run");
    }
}
