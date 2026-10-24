import com.google.zxing.*;
import com.google.zxing.common.HybridBinarizer;
import com.google.zxing.qrcode.QRCodeReader;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

class QrRoundTrip {
    public static void main(String[] args) throws Exception {
        BufferedReader input = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        String expected = new String(Base64.getDecoder().decode(input.readLine()), StandardCharsets.UTF_8);
        List<String> rows = input.lines().toList();
        int side = rows.size(), scale = 6;
        int[] pixels = new int[side * side * scale * scale];
        Arrays.fill(pixels, 0xFFFFFFFF);
        for (int y = 0; y < side * scale; y++) for (int x = 0; x < side * scale; x++)
            if (rows.get(y / scale).charAt(x / scale) == '1') pixels[y * side * scale + x] = 0xFF000000;
        BinaryBitmap bitmap = new BinaryBitmap(new HybridBinarizer(new RGBLuminanceSource(side * scale, side * scale, pixels)));
        String actual = new QRCodeReader().decode(bitmap).getText();
        if (!expected.equals(actual)) throw new AssertionError("QR payload mismatch");
        System.out.println("QR round trip OK");
    }
}
