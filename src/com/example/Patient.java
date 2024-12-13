package com.example;

public class Patient {
    private byte[] hoten, ngaysinh, gioitinh, quequan, mabenhnhan, sdt, pin, tieusu, diung, balance, picture;
    private short len_hoten, len_ns, len_gt, len_qq, len_sdt, len_mbn, len_pin, len_ts, len_du, len_balance, len_picture;

    public Patient() {
        hoten = new byte[80];
        gioitinh = new byte[80];
        ngaysinh = new byte[80];
        quequan = new byte[80];
        sdt = new byte[80];
        mabenhnhan = new byte[80];
        pin = new byte[8];
        tieusu = new byte[80];
        diung = new byte[80];
        balance = new byte[80];
        picture = new byte[32767];
    }

    // Getters and setters for each field
    public byte[] getHoten() { return hoten; }
    public void setHoten(byte[] hoten) { this.hoten = hoten; }

    public byte[] getNgaysinh() { return ngaysinh; }
    public void setNgaysinh(byte[] ngaysinh) { this.ngaysinh = ngaysinh; }

    public byte[] getGioitinh() { return gioitinh; }
    public void setGioitinh(byte[] gioitinh) { this.gioitinh = gioitinh; }

    public byte[] getQuequan() { return quequan; }
    public void setQuequan(byte[] quequan) { this.quequan = quequan; }

    public byte[] getSdt() { return sdt; }
    public void setSdt(byte[] sdt) { this.sdt = sdt; }

    public byte[] getMabenhnhan() { return mabenhnhan; }
    public void setMabenhnhan(byte[] mabenhnhan) { this.mabenhnhan = mabenhnhan; }

    public byte[] getPin() { return pin; }
    public void setPin(byte[] pin) { this.pin = pin; }

    public byte[] getTieusu() { return tieusu; }
    public void setTieusu(byte[] tieusu) { this.tieusu = tieusu; }

    public byte[] getDiung() { return diung; }
    public void setDiung(byte[] diung) { this.diung = diung; }

    public short getLenHoten() { return len_hoten; }
    public void setLenHoten(short len_hoten) { this.len_hoten = len_hoten; }

    public short getLenNs() { return len_ns; }
    public void setLenNs(short len_ns) { this.len_ns = len_ns; }

    public short getLenGt() { return len_gt; }
    public void setLenGt(short len_gt) { this.len_gt = len_gt; }

    public short getLenSdt() { return len_sdt; }
    public void setLenSdt(short len_sdt) { this.len_sdt = len_sdt; }

    public short getLenQq() { return len_qq; }
    public void setLenQq(short len_qq) { this.len_qq = len_qq; }

    public short getLenMbn() { return len_mbn; }
    public void setLenMbn(short len_mbn) { this.len_mbn = len_mbn; }

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
