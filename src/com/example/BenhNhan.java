package com.example;

import javacard.framework.*;
import javacardx.apdu.ExtendedLength;

public class BenhNhan extends Applet implements ExtendedLength{

    // Instance of the Patient class to hold patient information
    private static Patient patient;

	private static short MAX_SIZE = 1024;
	
	private static short dataLen;
    // Counter used for various operations, such as PIN attempts
    private static short counter;

    // Instruction codes for various APDU commands
    private static final byte INS_INIT_BN = (byte) 0x10; // Initialize patient information
    private static final byte UNBLOCK_CARD = (byte) 0x11; // Unblock the card
    private static final byte INS_RQPIN = (byte) 0x12; // Request PIN
    private static final byte INS_GETINFO = (byte) 0x13; // Get patient information
    private static final byte INS_GETTSBA = (byte) 0x14; // Get patient's medical history
    private static final byte INS_GETDU = (byte) 0x15; // Get patient's allergy information
    private static final byte INS_SETTIEUSU = (byte) 0x16; // Set patient's medical history
    private static final byte INS_SETCHATDU = (byte) 0x17; // Set patient's allergy information
    private static final byte CLEAR_CARD = (byte) 0x19; // Clear all patient data
    private static final byte CHECK_PIN = (byte) 0x20; // Check the PIN

    // Flag indicating whether the card is blocked
    private static boolean block_card = false;

    // Static array used for APDU responses
    private final static byte[] abc = {(byte) 0x3A, (byte) 0x00, (byte) 0x01};

    // Temporary buffer for various operations
    private static byte[] tempBuffer;

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new BenhNhan();
    }

public BenhNhan() {
    // Initialize the patient instance
    patient = new Patient();

    // Set patient details
    patient.setHoten(new byte[]{'M', 'a', 'i', ' ', 'T', 'r', 'u', 'n', 'g', ' ', 'K', 'i', 'e', 'n'});
    patient.setQuequan(new byte[]{'S', 'o', 'n', ' ', 'L', 'a'});
    patient.setNgaysinh(new byte[]{'0', '7', '/', '0', '6', '/', '2', '0', '0', '2'});
    patient.setGioitinh(new byte[]{'N', 'a', 'm'});
    patient.setMabenhnhan(new byte[]{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'});
    patient.setSdt(new byte[]{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'});
    patient.setPin(new byte[]{'1', '2', '3', '4', '5', '6', '7', '8'});

    // Initialize lengths (if needed)
    patient.setLenHoten((short) 14);
    patient.setLenQq((short) 6);
    patient.setLenNs((short) 10);
    patient.setLenGt((short) 3);
    patient.setLenMbn((short) 10);
    patient.setLenSdt((short) 10);
    patient.setLenPin((short) 8);

    // Register the applet
    register();

    // Create a transient buffer
    tempBuffer = JCSystem.makeTransientByteArray((short) MAX_SIZE, JCSystem.CLEAR_ON_DESELECT);

    // Initialize other variables
    counter = 3;

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
            	dataLen = apdu.getIncomingLength();
                if (dataLen > MAX_SIZE) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }
                short dataOffset = apdu.getOffsetCdata();
                pointer = 0;
                while (len > 0) {
                    Util.arrayCopy(buf, dataOffset, tempBuffer, pointer, len);
                    pointer += len;
                    len = apdu.receiveBytes(dataOffset);
                }
                init_bn(dataLen);
                break;
            case INS_RQPIN:
                get_pin(apdu);
                break;
            case INS_GETINFO:
                get_info_patient(apdu);
                break;
            case INS_GETTSBA:
                get_tieusu(apdu);
                break;
            case INS_GETDU:
                get_chatdu(apdu);
                break;
            case INS_SETTIEUSU:
                set_tsba(apdu, len);
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

		// Check the PIN
		if (Util.arrayCompare(buffer, ISO7816.OFFSET_CDATA, patient.getPin(), (short) 0, len) == 0) {
			// Correct PIN
			apdu.setOutgoingLength((short) 1);
			apdu.sendBytesLong(abc, (short) 1, (short) 1); // Send success response
		} else {
			// Incorrect PIN
			counter--;
			if (counter == 0) {
				block_card = true; // Block the card
				ISOException.throwIt((short) 0x6983); // Send "authentication method blocked" status
			} else {
				apdu.setOutgoingLength((short) 1);
				apdu.sendBytesLong(abc, (short) 2, (short) 1); // Send failure response
			}
		}
	}



    private void unblockcard(APDU apdu) {
        counter = 3;
        block_card = false;
    }

    private void clear_card(APDU apdu) {
        patient.setLenDu((short) 0);
        patient.setLenGt((short) 0);
        patient.setLenHoten((short) 0);
        patient.setLenMbn((short) 0);
        patient.setLenSdt((short)0);
        patient.setLenNs((short) 0);
        patient.setLenPin((short) 0);
        patient.setLenQq((short) 0);
        patient.setLenTs((short) 0);
        Util.arrayFillNonAtomic(patient.getHoten(), (short) 0, (short) 64, (byte) 0);
        Util.arrayFillNonAtomic(patient.getNgaysinh(), (short) 0, (short) 64, (byte) 0);
        Util.arrayFillNonAtomic(patient.getQuequan(), (short) 0, (short) 64, (byte) 0);
        Util.arrayFillNonAtomic(patient.getMabenhnhan(), (short) 0, (short) 64, (byte) 0);
        Util.arrayFillNonAtomic(patient.getGioitinh(), (short) 0, (short) 64, (byte) 0);
        Util.arrayFillNonAtomic(patient.getPin(), (short) 0, (short) 18, (byte) 0);
        Util.arrayFillNonAtomic(patient.getDiung(), (short) 0, (short) 64, (byte) 0);
        Util.arrayFillNonAtomic(patient.getTieusu(), (short) 0, (short) 64, (byte) 0);
    }

    private void get_pin(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		short pinLength = patient.getLenPin(); // Get the actual PIN length
		Util.arrayCopy(patient.getPin(), (short) 0, buffer, (short) 0, pinLength);
		apdu.setOutgoingAndSend((short) 0, pinLength);
	}
	
private void get_info_patient(APDU apdu) {
    byte[] buffer = apdu.getBuffer();

    // Calculate the total length with separators
    short totalLength = (short) (patient.getLenHoten() + 1 + patient.getLenNs() + 1 +
                                patient.getLenQq() + 1 + patient.getLenGt() + 1 +
                                patient.getLenMbn() + 1 + patient.getLenSdt());

    short le = apdu.setOutgoing();
    apdu.setOutgoingLength(totalLength);

    short pointer = 0;

    // Prepare the data to be sent
    byte[] data = new byte[totalLength];

    // Append fields with separators
    Util.arrayCopy(patient.getHoten(), (short) 0, data, pointer, patient.getLenHoten());
    pointer += patient.getLenHoten();
    data[pointer++] = (byte) 0x2E; // Separator '.'

    Util.arrayCopy(patient.getNgaysinh(), (short) 0, data, pointer, patient.getLenNs());
    pointer += patient.getLenNs();
    data[pointer++] = (byte) 0x2E; // Separator '.'

    Util.arrayCopy(patient.getQuequan(), (short) 0, data, pointer, patient.getLenQq());
    pointer += patient.getLenQq();
    data[pointer++] = (byte) 0x2E; // Separator '.'

    Util.arrayCopy(patient.getGioitinh(), (short) 0, data, pointer, patient.getLenGt());
    pointer += patient.getLenGt();
    data[pointer++] = (byte) 0x2E; // Separator '.'

    Util.arrayCopy(patient.getMabenhnhan(), (short) 0, data, pointer, patient.getLenMbn());
    pointer += patient.getLenMbn();
    data[pointer++] = (byte) 0x2E; // Separator '.'

    Util.arrayCopy(patient.getSdt(), (short) 0, data, pointer, patient.getLenSdt());
    pointer += patient.getLenSdt();

    // Send the data in chunks if necessary
    short sendLen;
    short remainingLength = totalLength;
    pointer = 0;

    while (remainingLength > 0) {
        sendLen = (remainingLength > le) ? le : remainingLength;
        apdu.sendBytesLong(data, pointer, sendLen);
        remainingLength -= sendLen;
        pointer += sendLen;
    }
}


    private void get_tieusu(APDU apdu) {
        if (patient.getLenTs() != 0) {
            byte[] buffer = apdu.getBuffer();
            apdu.setOutgoing();
            apdu.setOutgoingLength((short) 65);
            Util.arrayCopy(patient.getTieusu(), (short) 0, buffer, (short) 0, patient.getLenTs());
            apdu.sendBytes((short) 0, patient.getLenTs());
        }
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

    private void set_tsba(APDU apdu, short len) {
        patient.setLenTs(len);
        byte[] buffer = apdu.getBuffer();
        apdu.setOutgoing();
        apdu.setOutgoingLength((short) 65);
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, patient.getTieusu(), (short) 0, len);
	apdu.sendBytes((short) 0, len);
    }

    private void set_chatdu(APDU apdu, short len) {
        patient.setLenDu(len);
        byte[] buffer = apdu.getBuffer();
        apdu.setOutgoing();
        apdu.setOutgoingLength((short) 65);
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, patient.getDiung(), (short) 0, len);
        apdu.sendBytes((short) 0, len);
    }

	private void init_bn(short dataLen) {
		short tg1, tg2, tg3, tg4, tg5, tg6;
		tg1 = tg2 = tg3 = tg4 = tg5 = tg6 = 0;
		// Locate the positions of the delimiter '.'
		for (short i = 0; i < dataLen; i++) {
			if (tempBuffer[i] == (byte) 0x2e) { // 0x2e is the ASCII code for '.'
				if (tg1 == 0) {
					tg1 = i;
					patient.setLenHoten((short) tg1);
				} else if (tg2 == 0) {
					tg2 = i;
					patient.setLenNs((short) (tg2 - tg1 - 1));
				} else if (tg3 == 0) {
					tg3 = i;
					patient.setLenQq((short) (tg3 - tg2 - 1));
				} else if (tg4 == 0) {
					tg4 = i;
					patient.setLenGt((short) (tg4 - tg3 - 1));
				} else if(tg5 == 0){
					tg5 = i;
					patient.setLenSdt((short) (tg5 - tg4 - 1));
				} else {
					tg6 = i;
					patient.setLenMbn((short) (tg6 - tg5 - 1));
					short pinLength = (short) (dataLen - tg6 - 1); // Calculate actual PIN length
					if (pinLength > 8) {
						// Throw the appropriate status word
						ISOException.throwIt((short) 0x6A80);
						return; // Exit the method
					}
                patient.setLenPin(pinLength); // Set the valid PIN length
				}
			}
		}

		// Copy data to respective fields
		Util.arrayCopy(tempBuffer, (short) 0, patient.getHoten(), (short) 0, patient.getLenHoten());
		Util.arrayCopy(tempBuffer, (short) (tg1 + 1), patient.getNgaysinh(), (short) 0, patient.getLenNs());
		Util.arrayCopy(tempBuffer, (short) (tg2 + 1), patient.getQuequan(), (short) 0, patient.getLenQq());
		Util.arrayCopy(tempBuffer, (short) (tg3 + 1), patient.getGioitinh(), (short) 0, patient.getLenGt());
		Util.arrayCopy(tempBuffer, (short) (tg4 + 1), patient.getMabenhnhan(), (short) 0, patient.getLenMbn());
		Util.arrayCopy(tempBuffer, (short) (tg5 + 1), patient.getPin(), (short) 0, patient.getLenPin());
	}

}