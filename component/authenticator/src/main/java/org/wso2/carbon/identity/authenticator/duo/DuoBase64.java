/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.authenticator.duo;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * Base64 Utilities for Duo authenticator.
 */
public class DuoBase64 {
    /**
     * No options specified. Value is zero.
     */
    public static final int NO_OPTIONS = 0;

    /**
     * Specify encoding in first bit. Value is one.
     */
    public static final int ENCODE = 1;

    /**
     * Specify decoding in first bit. Value is zero.
     */
    public static final int DECODE = 0;

    /**
     * Specify that data should be gzip-compressed in second bit. Value is two.
     */
    public static final int GZIP = 2;

    /**
     * Specify that gzipped data should <em>not</em> be automatically gunzipped.
     */
    public static final int DONT_GUNZIP = 4;

    /**
     * Do break lines when encoding. Value is 8.
     */
    public static final int DO_BREAK_LINES = 8;

    /**
     * Encode using Base64-like encoding that is URL- and Filename-safe as
     * described in Section 4 of RFC3548: <a
     * href="http://www.faqs.org/rfcs/rfc3548.html"
     * >http://www.faqs.org/rfcs/rfc3548.html</a>. It is important to note that
     * data encoded this way is <em>not</em> officially valid Base64, or at the
     * very least should not be called Base64 without also specifying that is
     * was encoded using the URL- and Filename-safe dialect.
     */
    public static final int URL_SAFE = 16;

    /**
     * Encode using the special "ordered" dialect of Base64 described here: <a
     * href="http://www.faqs.org/qa/rfcc-1940.html">http://www.faqs.org/qa/rfcc-
     * 1940.html</a>.
     */
    public static final int ORDERED = 32;

    /**
     * Maximum line length (76) of Base64 output.
     */
    private static final int MAX_LINE_LENGTH = 76;

    /**
     * The equals sign (=) as a byte.
     */
    private static final byte EQUALS_SIGN = (byte) '=';

    /**
     * The new line character (\n) as a byte.
     */
    private static final byte NEW_LINE = (byte) '\n';

    /**
     * Preferred encoding.
     */
    private static final String PREFERRED_ENCODING = "US-ASCII";

    private static final byte WHITE_SPACE_ENC = -5; // Indicates white space in encoding
    private static final byte EQUALS_SIGN_ENC = -1; // Indicates equals sign in encoding

    /**
     * The 64 valid Base64 values.
     */
    private static final byte[] _STANDARD_ALPHABET = {(byte) 'A', (byte) 'B',
            (byte) 'C', (byte) 'D', (byte) 'E', (byte) 'F', (byte) 'G',
            (byte) 'H', (byte) 'I', (byte) 'J', (byte) 'K', (byte) 'L',
            (byte) 'M', (byte) 'N', (byte) 'O', (byte) 'P', (byte) 'Q',
            (byte) 'R', (byte) 'S', (byte) 'T', (byte) 'U', (byte) 'V',
            (byte) 'W', (byte) 'X', (byte) 'Y', (byte) 'Z', (byte) 'a',
            (byte) 'b', (byte) 'c', (byte) 'd', (byte) 'e', (byte) 'f',
            (byte) 'g', (byte) 'h', (byte) 'i', (byte) 'j', (byte) 'k',
            (byte) 'l', (byte) 'm', (byte) 'n', (byte) 'o', (byte) 'p',
            (byte) 'q', (byte) 'r', (byte) 's', (byte) 't', (byte) 'u',
            (byte) 'v', (byte) 'w', (byte) 'x', (byte) 'y', (byte) 'z',
            (byte) '0', (byte) '1', (byte) '2', (byte) '3', (byte) '4',
            (byte) '5', (byte) '6', (byte) '7', (byte) '8', (byte) '9',
            (byte) '+', (byte) '/'};

    /**
     * Translates a Base64 value to either its 6-bit reconstruction value or a
     * negative number indicating some other meaning.
     **/
    private static final byte[] _STANDARD_DECODABET = {-9, -9, -9, -9, -9, -9,
            -9, -9, -9, // Decimal 0 - 8
            -5, -5, // Whitespace: Tab and Linefeed
            -9, -9, // Decimal 11 - 12
            -5, // Whitespace: Carriage Return
            -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 14 -
            // 26
            -9, -9, -9, -9, -9, // Decimal 27 - 31
            -5, // Whitespace: Space
            -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 33 - 42
            62, // Plus sign at decimal 43
            -9, -9, -9, // Decimal 44 - 46
            63, // Slash at decimal 47
            52, 53, 54, 55, 56, 57, 58, 59, 60, 61, // Numbers zero through nine
            -9, -9, -9, // Decimal 58 - 60
            -1, // Equals sign at decimal 61
            -9, -9, -9, // Decimal 62 - 64
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, // Letters 'A' through
            // 'N'
            14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, // Letters 'O'
            // through 'Z'
            -9, -9, -9, -9, -9, -9, // Decimal 91 - 96
            26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, // Letters 'a'
            // through 'm'
            39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, // Letters 'n'
            // through 'z'
            -9, -9, -9, -9, -9 // Decimal 123 - 127
            , -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 128 -
            // 139
            -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 140 -
            // 152
            -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 153 -
            // 165
            -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 166 -
            // 178
            -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 179 -
            // 191
            -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 192 -
            // 204
            -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 205 -
            // 217
            -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 218 -
            // 230
            -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 231 -
            // 243
            -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9 // Decimal 244 - 255
    };

    /**
     * URL safe based64 alphabet
     * Used in the URL- and Filename.
     */
    private static final byte[] _URL_SAFE_ALPHABET = {(byte) 'A', (byte) 'B',
            (byte) 'C', (byte) 'D', (byte) 'E', (byte) 'F', (byte) 'G',
            (byte) 'H', (byte) 'I', (byte) 'J', (byte) 'K', (byte) 'L',
            (byte) 'M', (byte) 'N', (byte) 'O', (byte) 'P', (byte) 'Q',
            (byte) 'R', (byte) 'S', (byte) 'T', (byte) 'U', (byte) 'V',
            (byte) 'W', (byte) 'X', (byte) 'Y', (byte) 'Z', (byte) 'a',
            (byte) 'b', (byte) 'c', (byte) 'd', (byte) 'e', (byte) 'f',
            (byte) 'g', (byte) 'h', (byte) 'i', (byte) 'j', (byte) 'k',
            (byte) 'l', (byte) 'm', (byte) 'n', (byte) 'o', (byte) 'p',
            (byte) 'q', (byte) 'r', (byte) 's', (byte) 't', (byte) 'u',
            (byte) 'v', (byte) 'w', (byte) 'x', (byte) 'y', (byte) 'z',
            (byte) '0', (byte) '1', (byte) '2', (byte) '3', (byte) '4',
            (byte) '5', (byte) '6', (byte) '7', (byte) '8', (byte) '9',
            (byte) '-', (byte) '_'};

    /**
     * Used in decoding URL- and Filename-safe dialects of Base64.
     */
    private static final byte[] _URL_SAFE_DECODABET = {-9, -9, -9, -9, -9, -9,
            -9, -9, -9, // Decimal 0 - 8
            -5, -5, // Whitespace: Tab and Linefeed
            -9, -9, // Decimal 11 - 12
            -5, // Whitespace: Carriage Return
            -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 14 -
            // 26
            -9, -9, -9, -9, -9, // Decimal 27 - 31
            -5, // Whitespace: Space
            -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 33 - 42
            -9, // Plus sign at decimal 43
            -9, // Decimal 44
            62, // Minus sign at decimal 45
            -9, // Decimal 46
            -9, // Slash at decimal 47
            52, 53, 54, 55, 56, 57, 58, 59, 60, 61, // Numbers zero through nine
            -9, -9, -9, // Decimal 58 - 60
            -1, // Equals sign at decimal 61
            -9, -9, -9, // Decimal 62 - 64
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, // Letters 'A' through
            // 'N'
            14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, // Letters 'O'
            // through 'Z'
            -9, -9, -9, -9, // Decimal 91 - 94
            63, // Underscore at decimal 95
            -9, // Decimal 96
            26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, // Letters 'a'
            // through 'm'
            39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, // Letters 'n'
            // through 'z'
            -9, -9, -9, -9, -9 // Decimal 123 - 127
            , -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 128 -
            // 139
            -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 140 -
            // 152
            -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 153 -
            // 165
            -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 166 -
            // 178
            -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 179 -
            // 191
            -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 192 -
            // 204
            -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 205 -
            // 217
            -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 218 -
            // 230
            -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 231 -
            // 243
            -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9 // Decimal 244 - 255
    };

    /**
     * Ordered base64 alphabet.
     */
    private static final byte[] _ORDERED_ALPHABET = {(byte) '-', (byte) '0',
            (byte) '1', (byte) '2', (byte) '3', (byte) '4', (byte) '5',
            (byte) '6', (byte) '7', (byte) '8', (byte) '9', (byte) 'A',
            (byte) 'B', (byte) 'C', (byte) 'D', (byte) 'E', (byte) 'F',
            (byte) 'G', (byte) 'H', (byte) 'I', (byte) 'J', (byte) 'K',
            (byte) 'L', (byte) 'M', (byte) 'N', (byte) 'O', (byte) 'P',
            (byte) 'Q', (byte) 'R', (byte) 'S', (byte) 'T', (byte) 'U',
            (byte) 'V', (byte) 'W', (byte) 'X', (byte) 'Y', (byte) 'Z',
            (byte) '_', (byte) 'a', (byte) 'b', (byte) 'c', (byte) 'd',
            (byte) 'e', (byte) 'f', (byte) 'g', (byte) 'h', (byte) 'i',
            (byte) 'j', (byte) 'k', (byte) 'l', (byte) 'm', (byte) 'n',
            (byte) 'o', (byte) 'p', (byte) 'q', (byte) 'r', (byte) 's',
            (byte) 't', (byte) 'u', (byte) 'v', (byte) 'w', (byte) 'x',
            (byte) 'y', (byte) 'z'};

    /**
     * Used in decoding the "ordered" dialect of Base64.
     */
    private static final byte[] _ORDERED_DECODABET = {-9, -9, -9, -9, -9, -9,
            -9, -9, -9, // Decimal 0 - 8
            -5, -5, // Whitespace: Tab and Linefeed
            -9, -9, // Decimal 11 - 12
            -5, // Whitespace: Carriage Return
            -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 14 -
            // 26
            -9, -9, -9, -9, -9, // Decimal 27 - 31
            -5, // Whitespace: Space
            -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 33 - 42
            -9, // Plus sign at decimal 43
            -9, // Decimal 44
            0, // Minus sign at decimal 45
            -9, // Decimal 46
            -9, // Slash at decimal 47
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, // Numbers zero through nine
            -9, -9, -9, // Decimal 58 - 60
            -1, // Equals sign at decimal 61
            -9, -9, -9, // Decimal 62 - 64
            11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, // Letters 'A'
            // through 'M'
            24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, // Letters 'N'
            // through 'Z'
            -9, -9, -9, -9, // Decimal 91 - 94
            37, // Underscore at decimal 95
            -9, // Decimal 96
            38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, // Letters 'a'
            // through 'm'
            51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, // Letters 'n'
            // through 'z'
            -9, -9, -9, -9, -9 // Decimal 123 - 127
            , -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 128
            // - 139
            -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 140 -
            // 152
            -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 153 -
            // 165
            -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 166 -
            // 178
            -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 179 -
            // 191
            -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 192 -
            // 204
            -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 205 -
            // 217
            -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 218 -
            // 230
            -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 231 -
            // 243
            -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9 // Decimal 244 - 255
    };

    /**
     * Determine which alphabet
     * Returns one of the _SOMETHING_ALPHABET byte arrays depending on the
     * options specified.
     */
    private static final byte[] getAlphabet(int options) {
        if ((options & URL_SAFE) == URL_SAFE) {
            return _URL_SAFE_ALPHABET;
        } else if ((options & ORDERED) == ORDERED) {
            return _ORDERED_ALPHABET;
        } else {
            return _STANDARD_ALPHABET;
        }
    }

    /**
     * Returns one of the _SOMETHING_DECODABET byte arrays depending on the
     * options specified.
     */
    private static final byte[] getDecodabet(int options) {
        if ((options & URL_SAFE) == URL_SAFE) {
            return _URL_SAFE_DECODABET;
        } else if ((options & ORDERED) == ORDERED) {
            return _ORDERED_DECODABET;
        } else {
            return _STANDARD_DECODABET;
        }
    }

    /**
     * Defeats instantiation.
     */
    private DuoBase64() {
    }

    /**
     * Encoding Methods
     * Encodes up to the first three bytes of array threeBytes and
     * returns a four-byte array in Base64 notation. The actual number of
     * significant bytes in your array is given by numSigBytes.
     * The array threeBytes needs only be as big as numSigBytes. Code can reuse a byte array
     * by passing a four-byte array as b4.
     *
     * @param b4          A reusable byte array to reduce array instantiation
     * @param threeBytes  the array to convert
     * @param numSigBytes the number of significant bytes in your array
     * @return four byte array in Base64 notation.
     */
    private static byte[] encode3to4(byte[] b4, byte[] threeBytes, int numSigBytes, int options) {
        encode3to4(threeBytes, 0, numSigBytes, b4, 0, options);
        return b4;
    }

    /**
     * Encodes up to three bytes of the array source and writes the
     * resulting four Base64 bytes to destination. The source and
     * destination arrays can be manipulated anywhere along their length by
     * specifying srcOffset and destOffset. This method does not check to make sure
     * your arrays are large enough to accomodate srcOffset + 3 for the source array or
     * destOffset + 4 for the destination array.
     * The actual number of significant bytes in your array is given by numSigBytes.
     * This is the lowest level of the encoding methods with all possible parameters.
     *
     * @param source      the array to convert
     * @param srcOffset   the index where conversion begins
     * @param numSigBytes the number of significant bytes in your array
     * @param destination the array to hold the conversion
     * @param destOffset  the index where output will be put
     * @return the <var>destination</var> array
     */
    private static byte[] encode3to4(byte[] source, int srcOffset,
                                     int numSigBytes, byte[] destination, int destOffset, int options) {
        byte[] alphabet = getAlphabet(options);
        // 1 2 3
        // 01234567890123456789012345678901 Bit position
        // --------000000001111111122222222 Array position from threeBytes
        // --------| || || || | Six bit groups to index alphabet
        // >>18 >>12 >> 6 >> 0 Right shift necessary
        // 0x3f 0x3f 0x3f Additional AND
        // Create buffer with zero-padding if there are only one or two
        // significant bytes passed in the array.
        // We have to shift left 24 in order to flush out the 1's that appear
        // when Java treats a value as negative that is cast from a byte to an
        // int.
        int inBuff = (numSigBytes > 0 ? ((source[srcOffset] << 24) >>> 8) : 0)
                | (numSigBytes > 1 ? ((source[srcOffset + 1] << 24) >>> 16) : 0)
                | (numSigBytes > 2 ? ((source[srcOffset + 2] << 24) >>> 24) : 0);
        switch (numSigBytes) {
            case 3:
                destination[destOffset] = alphabet[(inBuff >>> 18)];
                destination[destOffset + 1] = alphabet[(inBuff >>> 12) & 0x3f];
                destination[destOffset + 2] = alphabet[(inBuff >>> 6) & 0x3f];
                destination[destOffset + 3] = alphabet[(inBuff) & 0x3f];
                return destination;
            case 2:
                destination[destOffset] = alphabet[(inBuff >>> 18)];
                destination[destOffset + 1] = alphabet[(inBuff >>> 12) & 0x3f];
                destination[destOffset + 2] = alphabet[(inBuff >>> 6) & 0x3f];
                destination[destOffset + 3] = EQUALS_SIGN;
                return destination;
            case 1:
                destination[destOffset] = alphabet[(inBuff >>> 18)];
                destination[destOffset + 1] = alphabet[(inBuff >>> 12) & 0x3f];
                destination[destOffset + 2] = EQUALS_SIGN;
                destination[destOffset + 3] = EQUALS_SIGN;
                return destination;
            default:
                return destination;
        }
    }

    /**
     * Encodes a byte array into Base64 notation. Does not GZip-compress data.
     *
     * @param source The data to convert
     * @return The data in Base64-encoded form
     * @throws NullPointerException if source array is null
     */
    public static String encodeBytes(byte[] source) {
        // Since we're not going to have the GZIP encoding turned on,
        // we're not going to have an java.io.IOException thrown, so
        // we should not force the user to have to catch it.
        String encoded = null;
        try {
            encoded = encodeBytes(source, 0, source.length, NO_OPTIONS);
        } catch (java.io.IOException ex) {
            assert false : ex.getMessage();
        }
        assert encoded != null;
        return encoded;
    }

    /**
     * Encodes a byte array into Base64 notation.
     *
     * @param source  The data to convert
     * @param off     Offset in array where conversion should begin
     * @param len     Length of data to convert
     * @param options Specified options
     * @return The Base64-encoded data as a String
     * @throws java.io.IOException      if there is an error
     * @throws NullPointerException     if source array is null
     * @throws IllegalArgumentException if source array, offset, or length are invalid
     */
    public static String encodeBytes(byte[] source, int off, int len,
                                     int options) throws java.io.IOException {
        byte[] encoded = encodeBytesToBytes(source, off, len, options);
        // Return value according to relevant encoding.
        try {
            return new String(encoded, PREFERRED_ENCODING);
        } catch (java.io.UnsupportedEncodingException uue) {
            return new String(encoded, StandardCharsets.UTF_8);
        }
    }

    /**
     * Similar to {@link #encodeBytes(byte[], int, int, int)} but returns a byte
     * array instead of instantiating a String. This is more efficient if you're
     * working with I/O streams and have large data sets to encode.
     *
     * @param source  The data to convert
     * @param off     Offset in array where conversion should begin
     * @param len     Length of data to convert
     * @param options Specified options
     * @return The Base64-encoded data as a String
     * @throws java.io.IOException      if there is an error
     * @throws NullPointerException     if source array is null
     * @throws IllegalArgumentException if source array, offset, or length are invalid
     */
    public static byte[] encodeBytesToBytes(byte[] source, int off, int len,
                                            int options) throws java.io.IOException {
        if (source == null) {
            throw new NullPointerException("Cannot serialize a null array.");
        }
        if (off < 0) {
            throw new IllegalArgumentException("Cannot have negative offset: " + off);
        }
        if (len < 0) {
            throw new IllegalArgumentException("Cannot have length offset: " + len);
        }
        if (off + len > source.length) {
            throw new IllegalArgumentException(String.format("Cannot have offset of %d and length of %d with array of" +
                    " length %d", off, len, source.length));
        }
        if ((options & GZIP) != 0) {
            java.io.ByteArrayOutputStream baos = null;
            java.util.zip.GZIPOutputStream gzos = null;
            DuoBase64.OutputStream b64os = null;
            try {
                // GZip -> Base64 -> ByteArray
                baos = new java.io.ByteArrayOutputStream();
                b64os = new DuoBase64.OutputStream(baos, ENCODE | options);
                gzos = new java.util.zip.GZIPOutputStream(b64os);
                gzos.write(source, off, len);
                gzos.close();
            } catch (java.io.IOException e) {
                // Catch it and then throw it immediately so that
                // the finally{} block is called for cleanup.
                throw e;
            } finally {
                try {
                    if (gzos != null) {
                        gzos.close();
                    }
                } catch (IOException ignored) {
                }
                try {
                    if (b64os != null) {
                        b64os.close();
                    }
                } catch (IOException ignored) {
                }
                try {
                    if (baos != null) {
                        baos.close();
                    }
                } catch (IOException ignored) {
                }
            }
            return baos.toByteArray();
        } else {
            // Else, don't compress. Better not to use streams at all then.
            boolean breakLines = (options & DO_BREAK_LINES) != 0;
            // int len43 = len * 4 / 3;
            // byte[] outBuff = new byte[ ( len43 ) // Main 4:3
            // + ( (len % 3) > 0 ? 4 : 0 ) // Account for padding
            // + (breakLines ? ( len43 / MAX_LINE_LENGTH ) : 0) ]; // New lines
            // Try to determine more precisely how big the array needs to be.
            // If we get it right, we don't have to do an array copy, and
            // we save a bunch of memory.
            int encLen = (len / 3) * 4 + (len % 3 > 0 ? 4 : 0); // Bytes needed for actual encoding
            if (breakLines) {
                encLen += encLen / MAX_LINE_LENGTH; // Plus extra newline
                // characters
            }
            byte[] outBuff = new byte[encLen];
            int d = 0;
            int e = 0;
            int len2 = len - 2;
            int lineLength = 0;
            for (; d < len2; d += 3, e += 4) {
                encode3to4(source, d + off, 3, outBuff, e, options);
                lineLength += 4;
                if (breakLines && lineLength >= MAX_LINE_LENGTH) {
                    outBuff[e + 4] = NEW_LINE;
                    e++;
                    lineLength = 0;
                }
            }
            if (d < len) {
                encode3to4(source, d + off, len - d, outBuff, e, options);
                e += 4;
            }
            // Only resize array if we didn't guess it right.
            if (e <= outBuff.length - 1) {
                // If breaking lines and the last byte falls right at
                // the line length (76 bytes per line), there will be
                // one extra byte, and the array will need to be resized.
                // Not too bad of an estimate on array size, I'd say.
                byte[] finalOut = new byte[e];
                System.arraycopy(outBuff, 0, finalOut, 0, e);
                return finalOut;
            } else {
                return outBuff;
            }
        }
    }

    /**
     * Decoding Methods
     * Decodes four bytes from array source and writes the resulting
     * bytes (up to three of them) to destination. The source and
     * destination arrays can be manipulated anywhere along their length by
     * specifying srcOffset and destOffset. This method does not check to make sure your
     * arrays are large enough to accomodate srcOffset + 4 for the source array or
     * destOffset + 3 for the destination array.
     * This method returns the actual number of bytes that were converted from the
     * Base64 encoding.This is the lowest level of the decoding methods with all possible
     * parameters.
     *
     * @param source      the array to convert
     * @param srcOffset   the index where conversion begins
     * @param destination the array to hold the conversion
     * @param destOffset  the index where output will be put
     * @param options     alphabet type is pulled from this (standard, url-safe,
     *                    ordered)
     * @return the number of decoded bytes converted
     * @throws NullPointerException     if source or destination arrays are null
     * @throws IllegalArgumentException if srcOffset or destOffset are invalid or there is not enough
     *                                  room in the array.
     */
    private static int decode4to3(byte[] source, int srcOffset,
                                  byte[] destination, int destOffset, int options) {
        // Lots of error checking and exception throwing
        if (source == null) {
            throw new NullPointerException("Source array was null.");
        }
        if (destination == null) {
            throw new NullPointerException("Destination array was null.");
        }
        if (srcOffset < 0 || srcOffset + 3 >= source.length) {
            throw new IllegalArgumentException(String.format("Source array with length %d cannot have offset of %d " +
                    "and still process four bytes.", source.length, srcOffset));
        }
        if (destOffset < 0 || destOffset + 2 >= destination.length) {
            throw new IllegalArgumentException(
                    String.format("Destination array with length %d cannot have offset of %d and still store three " +
                            "bytes.", destination.length, destOffset));
        }
        byte[] decodabet = getDecodabet(options);
        // Example: Dk==
        if (source[srcOffset + 2] == EQUALS_SIGN) {
            // Two ways to do the same thing. Don't know which way I like best.
            // int outBuff = ( ( decodabet[ source[ srcOffset ] ] << 24 ) >>> 6
            // )
            // | ( ( decodabet[ source[ srcOffset + 1] ] << 24 ) >>> 12 );
            int outBuff = ((decodabet[source[srcOffset]] & 0xFF) << 18)
                    | ((decodabet[source[srcOffset + 1]] & 0xFF) << 12);
            destination[destOffset] = (byte) (outBuff >>> 16);
            return 1;
        } else if (source[srcOffset + 3] == EQUALS_SIGN) {    // Example: DkL=

            // Two ways to do the same thing. Don't know which way I like best.
            // int outBuff = ( ( decodabet[ source[ srcOffset ] ] << 24 ) >>> 6
            // )
            // | ( ( decodabet[ source[ srcOffset + 1 ] ] << 24 ) >>> 12 )
            // | ( ( decodabet[ source[ srcOffset + 2 ] ] << 24 ) >>> 18 );
            int outBuff = ((decodabet[source[srcOffset]] & 0xFF) << 18)
                    | ((decodabet[source[srcOffset + 1]] & 0xFF) << 12)
                    | ((decodabet[source[srcOffset + 2]] & 0xFF) << 6);
            destination[destOffset] = (byte) (outBuff >>> 16);
            destination[destOffset + 1] = (byte) (outBuff >>> 8);
            return 2;
        } else {  // Example: DkLE
            // Two ways to do the same thing. Don't know which way I like best.
            // int outBuff = ( ( decodabet[ source[ srcOffset ] ] << 24 ) >>> 6
            // )
            // | ( ( decodabet[ source[ srcOffset + 1 ] ] << 24 ) >>> 12 )
            // | ( ( decodabet[ source[ srcOffset + 2 ] ] << 24 ) >>> 18 )
            // | ( ( decodabet[ source[ srcOffset + 3 ] ] << 24 ) >>> 24 );
            int outBuff = ((decodabet[source[srcOffset]] & 0xFF) << 18)
                    | ((decodabet[source[srcOffset + 1]] & 0xFF) << 12)
                    | ((decodabet[source[srcOffset + 2]] & 0xFF) << 6)
                    | ((decodabet[source[srcOffset + 3]] & 0xFF));
            destination[destOffset] = (byte) (outBuff >> 16);
            destination[destOffset + 1] = (byte) (outBuff >> 8);
            destination[destOffset + 2] = (byte) (outBuff);
            return 3;
        }
    }

    /**
     * Low-level access to decoding ASCII characters in the form of a byte
     * array. Ignores GUNZIP option, if it's set. This is not generally a recommended method,
     * although it is used internally as part of the decoding process. Special case:
     * if len = 0, an empty array is returned. Still, if you need more speed and
     * reduced memory footprint (and aren't gzipping), consider this method.
     *
     * @param source  The Base64 encoded data
     * @param off     The offset of where to begin decoding
     * @param len     The length of characters to decode
     * @param options Can specify options such as alphabet type to use
     * @return decoded data
     * @throws java.io.IOException If bogus characters exist in source data
     */
    public static byte[] decode(byte[] source, int off, int len, int options)
            throws java.io.IOException {
        if (source == null) {
            throw new NullPointerException("Cannot decode null source array.");
        }
        if (off < 0 || off + len > source.length) {
            throw new IllegalArgumentException(
                    String.format("Source array with length %d cannot have offset of %d and process %d bytes.",
                            source.length, off, len));
        }
        if (len == 0) {
            return new byte[0];
        } else if (len < 4) {
            throw new IllegalArgumentException("Base64-encoded string must have at least four characters, but length " +
                    "specified was " + len);
        }
        byte[] decodabet = getDecodabet(options);
        int len34 = len * 3 / 4; // Estimate on array size
        byte[] outBuff = new byte[len34]; // Upper limit on size of output
        int outBuffPosn = 0; // Keep track of where we're writing
        byte[] b4 = new byte[4]; // Four byte buffer from source, eliminating
        // white space
        int b4Posn = 0; // Keep track of four byte input buffer
        int i = 0; // Source array counter
        byte sbiDecode = 0; // Special value from decodabet
        for (i = off; i < off + len; i++) { // Loop through source
            sbiDecode = decodabet[source[i] & 0xFF];
            // White space, Equals sign, or legit Base64 character
            // Note the values such as -5 and -9 in the
            // DECODABETs at the top of the file.
            if (sbiDecode >= WHITE_SPACE_ENC) {
                if (sbiDecode >= EQUALS_SIGN_ENC) {
                    b4[b4Posn++] = source[i]; // Save non-whitespace
                    if (b4Posn > 3) { // Time to decode?
                        outBuffPosn += decode4to3(b4, 0, outBuff, outBuffPosn,
                                options);
                        b4Posn = 0;
                        // If that was the equals sign, break out of 'for' loop
                        if (source[i] == EQUALS_SIGN) {
                            break;
                        }
                    }
                }
            } else {
                // There's a bad input character in the Base64 stream.
                throw new java.io.IOException(String.format("Bad Base64 input character decimal %d in array position " +
                        "%d", ((int) source[i]) & 0xFF, i));
            }
        } // each input character
        byte[] out = new byte[outBuffPosn];
        System.arraycopy(outBuff, 0, out, 0, outBuffPosn);
        return out;
    }

    /**
     * Decodes data from Base64 notation, automatically detecting
     * gzip-compressed data and decompressing it.
     *
     * @param s the string to decode
     * @return the decoded data
     * @throws java.io.IOException If there is a problem
     */
    public static byte[] decode(String s) throws java.io.IOException {
        return decode(s, NO_OPTIONS);
    }

    /**
     * Decodes data from Base64 notation, automatically detecting
     * gzip-compressed data and decompressing it.
     *
     * @param s       the string to decode
     * @param options encode options such as URL_SAFE
     * @return the decoded data
     * @throws java.io.IOException  if there is an error
     * @throws NullPointerException if s is null
     */
    public static byte[] decode(String s, int options) throws java.io.IOException {
        if (s == null) {
            throw new NullPointerException("Input string was null.");
        }
        byte[] bytes;
        try {
            bytes = s.getBytes(PREFERRED_ENCODING);
        } catch (java.io.UnsupportedEncodingException uee) {
            bytes = s.getBytes(StandardCharsets.UTF_8);
        }
        // Decode
        bytes = decode(bytes, 0, bytes.length, options);
        // Check to see if it's gzip-compressed
        // GZIP Magic Two-Byte Number: 0x8b1f (35615)
        boolean dontGunzip = (options & DONT_GUNZIP) != 0;
        if (bytes.length >= 4 && !dontGunzip) {
            int head = ((int) bytes[0] & 0xff) | ((bytes[1] << 8) & 0xff00);
            if (java.util.zip.GZIPInputStream.GZIP_MAGIC == head) {
                java.io.ByteArrayInputStream bais = null;
                java.util.zip.GZIPInputStream gzis = null;
                java.io.ByteArrayOutputStream baos = null;
                byte[] buffer = new byte[2048];
                int length = 0;
                try {
                    baos = new java.io.ByteArrayOutputStream();
                    bais = new java.io.ByteArrayInputStream(bytes);
                    gzis = new java.util.zip.GZIPInputStream(bais);
                    while ((length = gzis.read(buffer)) >= 0) {
                        baos.write(buffer, 0, length);
                    }
                    // No error? Get new bytes.
                    bytes = baos.toByteArray();
                } catch (java.io.IOException e) {
                    throw new NullPointerException("Input was null.");
                } finally {
                    try {
                        if (baos != null) {
                            baos.close();
                        }
                    } catch (IOException ignored) {
                    }
                    try {
                        if (gzis != null) {
                            gzis.close();
                        }
                    } catch (IOException ignored) {
                    }
                    try {
                        if (bais != null) {
                            bais.close();
                        }
                    } catch (IOException ignored) {
                    }
                }
            }
        }
        return bytes;
    }

    /**
     * A {@link DuoBase64.OutputStream} will write data to anotherjava.io.OutputStream,
     * given in the constructor, and encode/decode to/from Base64 notation on the fly.
     */
    public static class OutputStream extends java.io.FilterOutputStream {
        private boolean encode;
        private int position;
        private byte[] buffer;
        private int bufferLength;
        private int lineLength;
        private boolean breakLines;
        private byte[] b4; // Scratch used in a few places
        private boolean suspendEncoding;
        private int options; // Record for later
        private byte[] decodabet; // Local copies to avoid extra method calls

        /**
         * Constructs a {@link DuoBase64.OutputStream} in ENCODE mode.
         *
         * @param out the <tt>java.io.OutputStream</tt> to which data will be written.
         */
        public OutputStream(java.io.OutputStream out) {
            this(out, ENCODE);
        }

        /**
         * Constructs a {@link DuoBase64.OutputStream} in either ENCODE or DECODE
         * mode.
         * Valid options:
         * ENCODE or DECODE: Encode or Decode as data is read.
         * DO_BREAK_LINES: don't break lines at 76 characters
         * (only meaningful when encoding)
         *
         * @param out     the java.io.OutputStream to which data will be
         *                written.
         * @param options Specified options.
         */
        public OutputStream(java.io.OutputStream out, int options) {
            super(out);
            this.breakLines = (options & DO_BREAK_LINES) != 0;
            this.encode = (options & ENCODE) != 0;
            this.bufferLength = encode ? 3 : 4;
            this.buffer = new byte[bufferLength];
            this.position = 0;
            this.lineLength = 0;
            this.suspendEncoding = false;
            this.b4 = new byte[4];
            this.options = options;
            this.decodabet = getDecodabet(options);
        }

        /**
         * Writes the byte to the output stream after converting to/from Base64
         * notation. When encoding, bytes are buffered three at a time before
         * the output stream actually gets a write() call. When decoding, bytes
         * are buffered four at a time.
         *
         * @param theByte the byte to write
         */
        @Override
        public void write(int theByte) throws java.io.IOException {
            // Encoding suspended?
            if (suspendEncoding) {
                this.out.write(theByte);
                return;
            }
            // Encode?
            if (encode) {
                buffer[position++] = (byte) theByte;
                if (position >= bufferLength) { // Enough to encode.
                    this.out
                            .write(encode3to4(b4, buffer, bufferLength, options));
                    lineLength += 4;
                    if (breakLines && lineLength >= MAX_LINE_LENGTH) {
                        this.out.write(NEW_LINE);
                        lineLength = 0;
                    }
                    position = 0;
                }
            } else {    // Else, Decoding
                // Meaningful Base64 character?
                if (decodabet[theByte & 0x7f] > WHITE_SPACE_ENC) {
                    buffer[position++] = (byte) theByte;
                    if (position >= bufferLength) { // Enough to output.
                        int len = DuoBase64.decode4to3(buffer, 0, b4, 0, options);
                        out.write(b4, 0, len);
                        position = 0;
                    }
                } else if (decodabet[theByte & 0x7f] != WHITE_SPACE_ENC) {
                    throw new java.io.IOException("Invalid character in Base64 data.");
                }
            }
        }

        /**
         * Calls {@link #write(int)} repeatedly until len bytes are written.
         *
         * @param theBytes array from which to read bytes
         * @param off      offset for array
         * @param len      max number of bytes to read into array
         */
        @Override
        public void write(byte[] theBytes, int off, int len) throws java.io.IOException {
            // Encoding suspended?
            if (suspendEncoding) {
                this.out.write(theBytes, off, len);
                return;
            }
            for (int i = 0; i < len; i++) {
                write(theBytes[off + i]);
            }
        }

        /**
         * This pads the buffer without closing the stream.
         *
         * @throws java.io.IOException if there's an error.
         */
        public void flushBase64() throws java.io.IOException {
            if (position > 0) {
                if (encode) {
                    out.write(encode3to4(b4, buffer, position, options));
                    position = 0;
                } else {
                    throw new java.io.IOException("Base64 input not properly padded.");
                }
            }
        }

        /**
         * Flushes and closes (in the superclass) the stream.
         */
        @Override
        public void close() throws java.io.IOException {
            // 1. Ensure that pending characters are written
            flushBase64();
            // 2. Actually close the stream
            // Base class both flushes and closes.
            super.close();
            buffer = null;
            out = null;
        }
    }
}
