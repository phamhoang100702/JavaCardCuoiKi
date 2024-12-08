package com.example;
public class Patient {
    private byte[] hoten, ngaysinh, gioitinh, quequan, mabenhnhan, pin, tieusu, diung;
    private short len_hoten, len_ns, len_gt, len_qq, len_mbn, len_pin, len_ts, len_du;

    public Patient() {
        hoten = new byte[64];
        gioitinh = new byte[64];
        ngaysinh = new byte[64];
        quequan = new byte[64];
        mabenhnhan = new byte[64];
        pin = new byte[8];
        tieusu = new byte[64];
        diung = new byte[64];
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
}