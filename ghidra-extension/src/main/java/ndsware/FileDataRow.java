package ndsware;

public class FileDataRow {
    private final String address;
    private final String hex;
    private final String ascii;

    public FileDataRow(String address, String hex, String ascii) {
        this.address = address;
        this.hex = hex;
        this.ascii = ascii;
    }

    public String getAddress() {
        return address;
    }

    public String getHex() {
        return hex;
    }

    public String getAscii() {
        return ascii;
    }
}
