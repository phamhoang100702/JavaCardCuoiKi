package com.example;

public class Patient {
    private byte[] pin, tieusu, diung, balance, picture, info;
    private short len_pin, len_ts, len_du, len_balance, len_picture, len_info;

    public Patient() {
    	info = new byte [1000];
        pin = new byte[8];
        tieusu = new byte[80];
        diung = new byte[80];
        balance = new byte[20];
        picture = new byte[32767];
    }

    // Getters and setters for each field
    public byte[] getInfo() { return info; }
    public void setInfo(byte[] hoten) { this.info = info; }
    
    public byte[] getPin() { return pin; }
    public void setPin(byte[] pin) { this.pin = pin; }

    public byte[] getTieusu() { return tieusu; }
    public void setTieusu(byte[] tieusu) { this.tieusu = tieusu; }

    public byte[] getDiung() { return diung; }
    public void setDiung(byte[] diung) { this.diung = diung; }

    public short getLenInfo() { return len_info; }
    public void setLenInfo(short len_info) { this.len_info = len_info; }

    public short getLenPin() { return len_pin; }
    public void setLenPin(short len_pin) { this.len_pin = len_pin; }

    public short getLenTs() { return len_ts; }
    public void setLenTs(short len_ts) { this.len_ts = len_ts; }

    public short getLenDu() { return len_du; }
    public void setLenDu(short len_du) { this.len_du = len_du; }

    public byte[] getBalance() { return balance; }
    public void setBalance(byte[] balance) { this.balance = balance; }

    public short getLenBalance() { return len_balance; }
    public void setLenBalance(short len_balance) { this.len_balance = len_balance; }

    public byte[] getPicture() { return picture; }
    public void setPicture(byte[] picture) { this.picture = picture; }

    public short getLenPicture() { return this.len_picture; }
    public void setLenPicture(short len_picture) { this.len_picture = len_picture; }
}
