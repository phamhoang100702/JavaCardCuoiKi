package com.example;

import javacard.framework.*;
import javacardx.apdu.ExtendedLength;
import javacard.security.*;
import javacardx.crypto.*;
import javacardx.shangmi.*;

public class BenhNhan extends Applet implements ExtendedLength {

    // Instance of the Patient class to hold patient information
    private static Patient patient;

    private static short MAX_SIZE = 32767;

    private static short dataLen;
    // Counter used for various operations, such as PIN attempts
    private static byte counter = 0;

    // Instruction codes for various APDU commands
    private static final byte INS_INIT_BN = (byte) 0x10; // Initialize patient information
    private static final byte UNBLOCK_CARD = (byte) 0x11; // Unblock the card
    private static final byte INS_RQPIN = (byte) 0x12; // Request PIN
    private static final byte INS_GETINFO = (byte) 0x13; // Get patient information
    private static final byte INS_GETBALANCE = (byte) 0x14; // Get patient's medical history
    private static final byte INS_GETDU = (byte) 0x15; // Get patient's allergy information
    private static final byte INS_UPDATEBALANCE = (byte) 0x16; // Set patient's medical history
    private static final byte INS_SETCHATDU = (byte) 0x17; // Set patient's allergy information
    private static final byte CLEAR_CARD = (byte) 0x18; // Clear all patient data
    private static final byte CHECK_PIN = (byte) 0x19; // Check the PIN
    private static final byte UPDATE_BN = (byte) 0x20; // Update patient data
    private static final byte UPDATE_PIN = (byte) 0x21; // Update patient pin
    private static final byte INS_UPDATE_PIC = (byte) 0x22; //Update patient picture
    private static final byte INS_GET_PIC = (byte) 0x23; //Send patient picture
    private static final byte INS_GET_PUBLIC_KEY = (byte) 0x24; //Update patient picture
    private static final byte INS_GET_SIGN = (byte) 0x25; //Send patient picture
	// AES key for encrypt and decrypt data
	private AESKey aesKey;
	private Cipher cipher;
	private short aesKeyLen;
	
	// Signature by RSA algorythm for verify
	private RSAPrivateKey rsaPrivKey;
    private RSAPublicKey rsaPubKey;
    private Signature rsaSig;
    
    // Random data to create AES key from PIN code
    private RandomData randomData;

    // Flag indicating whether the card is blocked
    private static boolean block_card = false;

    // Static array used for APDU responses
    private static byte[] abc = {
        (byte) 0x3A,
        (byte) 0x00,
        (byte) 0x01
    };

    // Temporary buffer for various operations
    private static byte[] tempBuffer;
    private static byte[] temp;

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new BenhNhan();
    }

    public BenhNhan() {
    	// init for AES
    	aesKeyLen = (short) (KeyBuilder.LENGTH_AES_128 / 8);
    	aesKey = (AESKey) (KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false));
    	cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
    	
    	// init for random data
    	randomData = RandomData.getInstance(RandomData.ALG_PSEUDO_RANDOM);
    	
    	// init for RSA
    	rsaSig = Signature.getInstance(Signature.ALG_RSA_MD5_PKCS1, false);
    	KeyPair keyPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_1024);
    	keyPair.genKeyPair();
    	rsaPrivKey = (RSAPrivateKey) keyPair.getPrivate();
    	rsaPubKey = (RSAPublicKey) keyPair.getPublic();
        
        randomData.setSeed(new byte[]{ 'H', 'e', 'l', 'l', 'o', 'W', 'o', 'r', 'l', 'd' }, (short) 0, (short) 10);
		byte[] keyData = new byte[aesKeyLen];
		randomData.generateData(keyData, (short) 0, aesKeyLen);
		aesKey.setKey(keyData, (short) 0);
		
        // Initialize the patient instance
        patient = new Patient();

        // Register the applet
        register();

        // Create a transient buffer
        tempBuffer = new byte[MAX_SIZE];
        temp = new byte[MAX_SIZE];
        // Request object deletion
        JCSystem.requestObjectDeletion();
    }

    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }
        byte[] buf = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();
        short pointer = 0;

        switch (buf[ISO7816.OFFSET_INS]) {
            case INS_INIT_BN:
                receiveInfo(apdu, buf, len);
                break;

            case UPDATE_BN:
                receiveInfo(apdu, buf, len);
                break;

            case UPDATE_PIN:
                update_pin(apdu, len);

            case INS_RQPIN:
                get_pin(apdu);
                break;

            case INS_GETINFO:
                // get_info_patient(apdu);
                sendInfo(apdu);
                break;

            case INS_GETBALANCE:
                get_balance(apdu);
                break;

            case INS_GETDU:
                get_chatdu(apdu);
                break;

            case INS_UPDATEBALANCE:
                update_balance(apdu, len);
                break;

            case INS_SETCHATDU:
                set_chatdu(apdu, len);
                break;

            case CLEAR_CARD:
                clear_card(apdu);
                break;

            case CHECK_PIN:
                processCard(apdu, len);
                break;

            case UNBLOCK_CARD:
                unblockcard(apdu);
                break;
            case INS_UPDATE_PIC:
                receivePicture(apdu, buf, len);
                break;
            case INS_GET_PIC:
                sendPicture(apdu);
                break;
            case (byte) INS_GET_PUBLIC_KEY:
				get_public_key(apdu, buf);
				break;
			case (byte) INS_GET_SIGN:
				sign_data(apdu, buf, len);
				break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                break;
        }
    }

    private void processCard(APDU apdu, short len) {
        byte[] buffer = apdu.getBuffer();
        apdu.setOutgoing();

        // If the card is already blocked
        if (block_card) {
            // Set status word 6983 to indicate "authentication method blocked"
            ISOException.throwIt((short) 0x6983);
            return;
        }

        // Check if the provided PIN length matches the stored PIN length
        if (len != patient.getLenPin()) {
            counter++; // Decrease counter for incorrect PIN
            if (counter == 4) {
                block_card = true; // Block the card
                ISOException.throwIt((short) 0x6983); // Send "authentication method blocked" status
            } else {
                apdu.setOutgoingLength((short) 1);
				// Convert the counter value to a byte and send it as the response
				byte[] response = new byte[1];
				response[0] = (byte) counter; // Set the response to the current counter value
				apdu.sendBytesLong(response, (short) 0, (short) 1); // Send failure response
            }
            return;
        }

        // Check the PIN
        if (Util.arrayCompare(buffer, ISO7816.OFFSET_CDATA, patient.getPin(), (short) 0, len) == 0) {
            // Correct PIN
            counter = 0; // Reset counter
            apdu.setOutgoingLength((short) 1);
            apdu.sendBytesLong(abc, (short) 1, (short) 1); // Send success response
        } else {
            // Incorrect PIN
            counter++; // Decrease counter
            if (counter == 4) {
                block_card = true; // Block the card
                ISOException.throwIt((short) 0x6983); // Send "authentication method blocked" status
            } else {
                apdu.setOutgoingLength((short) 1);
				// Convert the counter value to a byte and send it as the response
				byte[] response = new byte[1];
				response[0] = (byte) counter; // Set the response to the current counter value
				apdu.sendBytesLong(response, (short) 0, (short) 1); // Send failure response
            }
        }
    }


    private void unblockcard(APDU apdu) {
        counter = 0;
        block_card = false;
    }

    private void clear_card(APDU apdu) {
        patient.setLenInfo((short) 0);
        patient.setLenPin((short) 0);
        patient.setLenTs((short) 0);
        Util.arrayFillNonAtomic(patient.getInfo(), (short) 0, (short) 1000, (byte) 0);
        Util.arrayFillNonAtomic(patient.getPin(), (short) 0, (short) 8, (byte) 0);
        Util.arrayFillNonAtomic(patient.getDiung(), (short) 0, (short) 64, (byte) 0);
        Util.arrayFillNonAtomic(patient.getTieusu(), (short) 0, (short) 64, (byte) 0);
    }

    private void get_pin(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short pinLength = patient.getLenPin(); // Get the actual PIN length
        Util.arrayCopy(patient.getPin(), (short) 0, buffer, (short) 0, pinLength);
        apdu.setOutgoingAndSend((short) 0, pinLength);
    }

    private void get_balance(APDU apdu) {
            byte[] buffer = apdu.getBuffer();
            apdu.setOutgoing();
            apdu.setOutgoingLength(patient.getLenBalance());
            Util.arrayCopy(patient.getBalance(), (short) 0, buffer, (short) 0, patient.getLenBalance());
            apdu.sendBytes((short) 0, patient.getLenBalance());     
    }

    private void update_balance(APDU apdu, short len) {
		byte[] buffer = apdu.getBuffer();
		// Retrieve the new balance from the APDU buffer
		Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, patient.getBalance(), (short) 0, len);		
		// Update the patient balance length
		patient.setLenBalance(len);
    }

    private void set_chatdu(APDU apdu, short len) {
        patient.setLenDu(len);
        byte[] buffer = apdu.getBuffer();
        apdu.setOutgoing();
        apdu.setOutgoingLength((short) 65);
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, patient.getDiung(), (short) 0, len);
        apdu.sendBytes((short) 0, len);
    }


    private void get_chatdu(APDU apdu) {
        if (patient.getLenDu() != 0) {
            byte[] buffer = apdu.getBuffer();
            apdu.setOutgoing();
            apdu.setOutgoingLength((short) 65);
            Util.arrayCopy(patient.getDiung(), (short) 0, buffer, (short) 0, patient.getLenDu());
            apdu.sendBytes((short) 0, patient.getLenDu());
        }
    }
    
    private void update_pin(APDU apdu, short len) {
        try {
            // Check if the PIN length is greater than 8
            if (len > 8) {
                // Return an error status word for wrong length (6700)
                ISOException.throwIt((short) 0x6700);
            }

            // Update PIN length in the patient object
            patient.setLenPin(len);

            // Retrieve the buffer from the APDU object
            byte[] buffer = apdu.getBuffer();

            // Copy the new PIN from the buffer to the patient's PIN field
            Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, patient.getPin(), (short) 0, len);

            // Set a success status word (9000)
            ISOException.throwIt(ISO7816.SW_NO_ERROR);
        } catch (ISOException e) {
            // Handle ISOException and set appropriate status word
            ISOException.throwIt(e.getReason());
        } catch (Exception e) {
            // Handle any other exceptions and set status word 6F00
            ISOException.throwIt((short) 0x6F00);
        }
    }
    
    private void receiveInfo(APDU apdu, byte[] buf, short recvLen) {
    // Get the total length of incoming data
    dataLen = apdu.getIncomingLength();
    patient.setLenInfo(dataLen);
    if (dataLen > patient.getInfo().length) {
        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }

    // Get the offset where data starts
    short dataOffset = apdu.getOffsetCdata();
    short pointer = 0;

    while (recvLen > 0) {
        // Copy received data into the patient's info attribute
        Util.arrayCopy(buf, dataOffset, patient.getInfo(), pointer, recvLen);
        pointer += recvLen;

        // Continue receiving the next chunk
        recvLen = apdu.receiveBytes(dataOffset);
    }
}

private void sendInfo(APDU apdu) {
    short toSend = patient.getLenInfo();
    byte[] info = patient.getInfo();
    short le = apdu.setOutgoing(); // Maximum length to send
    apdu.setOutgoingLength(toSend);

    short sendLen;
    short pointer = 0;

    while (toSend > 0) {
        sendLen = (toSend > le) ? le : toSend;
        apdu.sendBytesLong(info, pointer, sendLen);
        toSend -= sendLen;
        pointer += sendLen;
    }
}

    private void receivePicture(APDU apdu, byte[] buf, short recvLen) {
        dataLen = apdu.getIncomingLength();
        patient.setLenPicture(dataLen);
        // Get the total length of incoming data
        if (dataLen > patient.getPicture().length) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Get the offset where data starts
        short dataOffset = apdu.getOffsetCdata();
        short pointer = 0;

        while (recvLen > 0) {
        	byte[] encryptedData = encryptAes(buf);
            // Copy received data into the patient's picture attribute
            Util.arrayCopy(encryptedData, dataOffset, patient.getPicture(), pointer, recvLen);
            pointer += recvLen;

            // Continue receiving the next chunk
            recvLen = apdu.receiveBytes(dataOffset);
        }

    }

    private void sendPicture(APDU apdu) {
    	byte[] encryptedImage = patient.getPicture();
    	byte[] decryptedPic = decryptAes(encryptedImage);
        short toSend = (short) decryptedPic.length;
        //short toSend = patient.getLenPicture();
        //byte[] picture = patient.getPicture();
        short le = apdu.setOutgoing(); // Maximum length to send
        apdu.setOutgoingLength(toSend);

        short sendLen;
        short pointer = 0;

        while (toSend > 0) {
            sendLen = (toSend > le) ? le : toSend;
            apdu.sendBytesLong(decryptedPic, pointer, sendLen);
            toSend -= sendLen;
            pointer += sendLen;
        }
    }
    
    private void setAesKeyFromPinCode() {
    	JCSystem.beginTransaction();
	    try {
		    randomData.setSeed(patient.getPin(), (short) 0, (short) patient.getPin().length);
			byte[] keyData = new byte[aesKeyLen];
			randomData.generateData(keyData, (short) 0, aesKeyLen);
			aesKey.setKey(keyData, (short) 0);
			JCSystem.commitTransaction();
	    } catch (Exception e) {
		    JCSystem.abortTransaction();
		    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
	    }
    }
    
    private byte[] encryptAes(byte[] dataToEncrypt) {
    	short paddingLength = (short) (16 - (dataToEncrypt.length % 16));
    	byte[] paddedData = new byte[(short) (dataToEncrypt.length + paddingLength)];
    	Util.arrayCopy(dataToEncrypt, (short) 0, paddedData, (short) 0, (short) dataToEncrypt.length);
    	for (byte i = 0; i < (byte) (paddingLength - 1); i++) paddedData[(short) (dataToEncrypt.length + 1)] = (byte) 0xFF;
    	paddedData[(short) (paddedData.length - 1)] = (byte) paddingLength;
	    cipher.init(aesKey, Cipher.MODE_ENCRYPT);
	    byte[] encryptedData = new byte[(short) paddedData.length];
	    cipher.doFinal(paddedData, (short) 0, (short) paddedData.length, encryptedData, (short) 0);
	    return encryptedData;
    }
    
    private byte[] decryptAes(byte[] dataToDecrypt) {
	    cipher.init(aesKey, Cipher.MODE_DECRYPT);
	    byte[] decryptedData = new byte[(short) dataToDecrypt.length];
	    cipher.doFinal(dataToDecrypt, (short) 0, (short) dataToDecrypt.length, decryptedData, (short) 0);
	    short paddingLength = (short) decryptedData[(short) (decryptedData.length - 1)];
	    byte[] unpaddedData = new byte[(short) (decryptedData.length - paddingLength)];
	    Util.arrayCopy(decryptedData, (short) 0, unpaddedData, (short) 0, (short) unpaddedData.length);
	    return unpaddedData;
    }
    
    private void get_public_key(APDU apdu, byte[] buf) {
	    short modLength = rsaPubKey.getModulus(buf, (short) 0);
		short expLength = rsaPubKey.getExponent(buf, modLength);
		apdu.setOutgoingAndSend((short) 0, (short) (modLength + expLength));
    }
    
    private void sign_data(APDU apdu, byte[] buf, short dataLength) {
	    byte[] dataToSign = new byte[dataLength];
	    Util.arrayCopy(buf, ISO7816.OFFSET_CDATA, dataToSign, (short) 0, dataLength);
	    byte[] signedData = signRsa(dataToSign);
	    Util.arrayCopy(signedData, (short) 0, buf, (short) 0, (short) signedData.length);
	    apdu.setOutgoingAndSend((short) 0, (short) signedData.length);
    }
    
    
    private byte[] signRsa(byte[] dataToSign) {
	    rsaSig.init(rsaPrivKey, Signature.MODE_SIGN);
	    byte[] signedBuffer = new byte[(short) (KeyBuilder.LENGTH_RSA_1024 / 8)];
	    rsaSig.sign(dataToSign, (short) 0, (short) dataToSign.length, signedBuffer, (short) 0);
	    return signedBuffer;
    }
}