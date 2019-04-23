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
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;


public class ClientWithAP {

    public static void main(String[] args) {

        String filename = "nokia_ringtone.mp3";
        if (args.length > 0) filename = args[0];

        String serverAddress = "localhost";
        if (args.length > 1) filename = args[1];

        int port = 4321;
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
            X509Certificate CAcert =(X509Certificate)cf.generateCertificate(fis);

            PublicKey PubKey = CAcert.getPublicKey();
            Cipher dcipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
//            dcipher.init(Cipher.DECRYPT_MODE,PubKey);

            toServer.writeUTF("Hello SecStore, please prove your identity!");
            int challengeSize = fromServer.readInt();
            byte[] challenge = new byte[challengeSize];
//            BufferedInputStream serverCertBuffer = new BufferedInputStream(fromServer);
            fromServer.readFully(challenge,0,challengeSize);
            String challengeMessage = fromServer.readUTF();

            toServer.writeUTF("Give me your certificate signed by CA");


            X509Certificate ServerCert =(X509Certificate)cf.generateCertificate(fromServer);
            PublicKey serverKey = ServerCert.getPublicKey();
            ServerCert.checkValidity();
            ServerCert.verify(PubKey);
            System.out.println("Cert Verified =)");

            dcipher.init(Cipher.DECRYPT_MODE,serverKey);
//            byte[] decryptedChallenge = new byte[256];
            System.out.println("Challenge length is "+challengeSize);
//            dcipher.update(challenge,0,challengeSize,decryptedChallenge);
            byte[] decryptedChallenge = dcipher.doFinal(challenge);
            if((new String(decryptedChallenge)).compareTo(challengeMessage)!=0){
                System.out.println("Challenge verification failed");
                System.out.println("Decrypted Message is : "+new String(decryptedChallenge));
                System.out.println("Challenge message is : "+challengeMessage);
                clientSocket.close();
            }

            System.out.println("Successful authentication with server :)");


            System.out.println("Sending file...");

            SecureRandom random2 = new SecureRandom();
            byte keybytes[] = new byte[12];
            random2.nextBytes(keybytes);
            Base64.Encoder keyencoder = Base64.getUrlEncoder().withoutPadding();
            String keytoken = keyencoder.encodeToString(keybytes);

            SecretKeySpec secretKey = new SecretKeySpec(keytoken.getBytes(),"AES");

            Cipher encryptCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            encryptCipher.init(Cipher.ENCRYPT_MODE,secretKey);

//             Send the filename and the keytoken
            toServer.writeInt(0);
            toServer.writeInt(filename.getBytes().length);
            toServer.writeInt(keytoken.getBytes().length);
            System.out.println("Keytoken char size is :"+ keytoken.length());
//            System.out.println(filename.getBytes().length);
            toServer.write(filename.getBytes());
            toServer.write(keytoken.getBytes());

            // Open the file
            fileInputStream = new FileInputStream(filename);
            bufferedFileInputStream = new BufferedInputStream(fileInputStream);

            byte [] fromFileBuffer = new byte[117];

            // Send the encrypted file
            for (boolean fileEnded = false; !fileEnded;) {
                numBytes = bufferedFileInputStream.read(fromFileBuffer);
//                System.out.println(numBytes);
                fileEnded = numBytes < 117;
                byte[] encryptedBytes =  encryptCipher.doFinal(fromFileBuffer);
                toServer.writeInt(1);
                toServer.writeInt(numBytes);
                toServer.writeInt(encryptedBytes.length);
                toServer.write(encryptedBytes);
                toServer.flush();
            }

            bufferedFileInputStream.close();
            fileInputStream.close();

            System.out.println("Closing connection...");

        } catch (Exception e) {e.printStackTrace();}

        long timeTaken = System.nanoTime() - timeStarted;
        System.out.println("Program took: " + timeTaken/1000000.0 + "ms to run");
    }
}