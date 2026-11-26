package org.morandi.proxy;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;

/** Framing used by the isolated HTTP/1.0 fixture, which declares an ASCII body length. */
record FixtureHttpResponse(int status, String body) {
    private static final int MAX_BYTES = 8_192;

    static FixtureHttpResponse read(InputStream wire) throws IOException {
        BufferedInputStream input = new BufferedInputStream(wire);
        ByteArrayOutputStream header = new ByteArrayOutputStream();
        int tail = 0;
        try {
            do {
                int value = input.read();
                if (value == -1) throw new EOFException("Incomplete fixture headers");
                if (header.size() == MAX_BYTES) throw new IOException("Fixture headers too large");
                header.write(value);
                tail = (tail << 8) | value;
            } while (tail != 0x0d0a0d0a);
        } catch (SocketTimeoutException failure) {
            throw new IOException("Fixture timed out reading headers (" + header.size() + " bytes)", failure);
        }
        String[] lines = header.toString(StandardCharsets.US_ASCII.name()).split("\r\n");
        String[] status = lines[0].split(" ", 3);
        if (status.length < 2 || !status[0].equals("HTTP/1.0") || !status[1].matches("[0-9]{3}")) {
            throw new IOException("Invalid fixture status line");
        }
        int length = -1;
        for (int i = 1; i < lines.length; i++) {
            int colon = lines[i].indexOf(':');
            if (colon < 0 || !lines[i].substring(0, colon).equalsIgnoreCase("Content-Length")) continue;
            String value = lines[i].substring(colon + 1).trim();
            if (length >= 0 || !value.matches("[0-9]{1,4}")) throw new IOException("Invalid fixture length");
            length = Integer.parseInt(value);
        }
        if (length < 0 || header.size() + length > MAX_BYTES) throw new IOException("Invalid fixture length");
        byte[] body = new byte[length];
        try {
            new DataInputStream(input).readFully(body);
        } catch (SocketTimeoutException failure) {
            throw new IOException("Fixture timed out reading body after HTTP " + status[1], failure);
        }
        return new FixtureHttpResponse(Integer.parseInt(status[1]), new String(body, StandardCharsets.US_ASCII));
    }
}
