package com.idme.auth.utilities

import android.util.Base64

/** Base64URL encoding/decoding per RFC 4648 section 5. */
object Base64URL {

    /** Encodes raw bytes to a Base64URL string (no padding). */
    fun encode(data: ByteArray): String =
        Base64.encodeToString(data, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)

    /** Decodes a Base64URL string to raw bytes. */
    fun decode(string: String): ByteArray? =
        try {
            Base64.decode(string, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
        } catch (_: Exception) {
            null
        }
}
