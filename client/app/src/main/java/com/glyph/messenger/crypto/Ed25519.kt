package com.glyph.messenger.crypto

import java.math.BigInteger
import java.security.MessageDigest
import java.util.Arrays

/**
 * Pure-Kotlin RFC 8032 Ed25519 digital signature engine.
 * Self-contained, zero-dependency, and verified against NIST/RFC test vectors.
 */
object Ed25519 {
    private val P: BigInteger = BigInteger.valueOf(2).pow(255).subtract(BigInteger.valueOf(19))
    private val L: BigInteger = BigInteger.valueOf(2).pow(252).add(BigInteger("27742317777372353535851937790883648493"))
    private val D: BigInteger = BigInteger.valueOf(-121665).multiply(BigInteger.valueOf(121666).modInverse(P)).mod(P)
    private val I: BigInteger = BigInteger.valueOf(2).modPow(P.subtract(BigInteger.ONE).divide(BigInteger.valueOf(4)), P)

    private val BY: BigInteger = BigInteger.valueOf(4).multiply(BigInteger.valueOf(5).modInverse(P)).mod(P)
    private val BX: BigInteger

    init {
        val u = BY.pow(2).subtract(BigInteger.ONE).mod(P)
        val v = D.multiply(BY.pow(2)).add(BigInteger.ONE).mod(P)
        val x = u.multiply(v.modInverse(P)).mod(P)
        var x2 = x.modPow(P.add(BigInteger.valueOf(3)).divide(BigInteger.valueOf(8)), P)
        if (!x2.pow(2).subtract(x).mod(P).equals(BigInteger.ZERO)) {
            x2 = x2.multiply(I).mod(P)
        }
        if (x2.testBit(0)) {
            x2 = P.subtract(x2)
        }
        BX = x2
    }

    private data class Point(val x: BigInteger, val y: BigInteger)

    private fun add(p1: Point, p2: Point): Point {
        val x1 = p1.x
        val y1 = p1.y
        val x2 = p2.x
        val y2 = p2.y
        val numX = x1.multiply(y2).add(y1.multiply(x2)).mod(P)
        val denX = BigInteger.ONE.add(D.multiply(x1).multiply(x2).multiply(y1).multiply(y2)).mod(P)
        val numY = y1.multiply(y2).add(x1.multiply(x2)).mod(P)
        val denY = BigInteger.ONE.subtract(D.multiply(x1).multiply(x2).multiply(y1).multiply(y2)).mod(P)
        return Point(numX.multiply(denX.modInverse(P)).mod(P), numY.multiply(denY.modInverse(P)).mod(P))
    }

    private fun mul(p: Point, k: BigInteger): Point {
        var r = Point(BigInteger.ZERO, BigInteger.ONE)
        var base = p
        val bitLen = k.bitLength()
        for (i in 0 until bitLen) {
            if (k.testBit(i)) {
                r = add(r, base)
            }
            base = add(base, base)
        }
        return r
    }

    private fun sha512(vararg parts: ByteArray): ByteArray {
        val md = MessageDigest.getInstance("SHA-512")
        for (p in parts) md.update(p)
        return md.digest()
    }

    private fun encodePoint(p: Point): ByteArray {
        val s = toLittleEndian(p.y, 32)
        if (p.x.testBit(0)) {
            s[31] = (s[31].toInt() or 0x80).toByte()
        }
        return s
    }

    private fun toLittleEndian(n: BigInteger, len: Int): ByteArray {
        val b = n.toByteArray()
        val out = ByteArray(len)
        var i = 0
        while (i < b.size && i < len) {
            out[i] = b[b.size - 1 - i]
            i++
        }
        return out
    }

    private fun fromLittleEndian(b: ByteArray, offset: Int, len: Int): BigInteger {
        val rev = ByteArray(len + 1)
        for (i in 0 until len) {
            rev[len - i] = b[offset + i]
        }
        return BigInteger(rev)
    }

    /**
     * Derives 32-byte Ed25519 compressed public key from 32-byte private seed.
     */
    fun derivePublicKey(seed: ByteArray): ByteArray {
        require(seed.size == 32) { "Seed must be 32 bytes" }
        val h = sha512(seed)
        h[0] = (h[0].toInt() and 248).toByte()
        h[31] = (h[31].toInt() and 127).toByte()
        h[31] = (h[31].toInt() or 64).toByte()
        val a = fromLittleEndian(h, 0, 32)
        val aPoint = mul(Point(BX, BY), a)
        return encodePoint(aPoint)
    }

    /**
     * Signs message using 32-byte private seed according to RFC 8032.
     * Returns 64-byte Ed25519 signature (R || S).
     */
    fun sign(seed: ByteArray, msg: ByteArray): ByteArray {
        require(seed.size == 32) { "Seed must be 32 bytes" }
        val h = sha512(seed)
        h[0] = (h[0].toInt() and 248).toByte()
        h[31] = (h[31].toInt() and 127).toByte()
        h[31] = (h[31].toInt() or 64).toByte()
        val a = fromLittleEndian(h, 0, 32)

        val aPoint = mul(Point(BX, BY), a)
        val pubKey = encodePoint(aPoint)

        val prefix = Arrays.copyOfRange(h, 32, 64)
        val rHash = sha512(prefix, msg)
        val r = fromLittleEndian(rHash, 0, 64).mod(L)

        val rPoint = mul(Point(BX, BY), r)
        val rBytes = encodePoint(rPoint)

        val kHash = sha512(rBytes, pubKey, msg)
        val k = fromLittleEndian(kHash, 0, 64).mod(L)

        val s = r.add(k.multiply(a)).mod(L)
        val sBytes = toLittleEndian(s, 32)

        val sig = ByteArray(64)
        System.arraycopy(rBytes, 0, sig, 0, 32)
        System.arraycopy(sBytes, 0, sig, 32, 32)
        return sig
    }

    private fun decodePoint(s: ByteArray): Point? {
        if (s.size != 32) return null
        val yBytes = s.copyOf()
        val xBit = (yBytes[31].toInt() and 0x80) != 0
        yBytes[31] = (yBytes[31].toInt() and 0x7F).toByte()
        val y = fromLittleEndian(yBytes, 0, 32).mod(P)

        val u = y.pow(2).subtract(BigInteger.ONE).mod(P)
        val v = D.multiply(y.pow(2)).add(BigInteger.ONE).mod(P)
        val vInv = try { v.modInverse(P) } catch (e: Exception) { return null }
        val x2 = u.multiply(vInv).mod(P)

        if (x2.equals(BigInteger.ZERO)) {
            if (xBit) return null
            return Point(BigInteger.ZERO, y)
        }

        var x = x2.modPow(P.add(BigInteger.valueOf(3)).divide(BigInteger.valueOf(8)), P)
        if (!x.pow(2).subtract(x2).mod(P).equals(BigInteger.ZERO)) {
            x = x.multiply(I).mod(P)
        }
        if (!x.pow(2).subtract(x2).mod(P).equals(BigInteger.ZERO)) {
            return null
        }
        if (x.testBit(0) != xBit) {
            x = P.subtract(x)
        }
        return Point(x, y)
    }

    /**
     * Verifies an RFC 8032 Ed25519 signature.
     * Returns true if valid, false otherwise.
     */
    fun verify(pubKey: ByteArray, msg: ByteArray, sig: ByteArray): Boolean {
        if (pubKey.size != 32 || sig.size != 64) return false
        val rBytes = Arrays.copyOfRange(sig, 0, 32)
        val sBytes = Arrays.copyOfRange(sig, 32, 64)

        val s = fromLittleEndian(sBytes, 0, 32)
        if (s >= L || s < BigInteger.ZERO) return false

        val aPoint = decodePoint(pubKey) ?: return false
        val rPoint = decodePoint(rBytes) ?: return false

        val kHash = sha512(rBytes, pubKey, msg)
        val k = fromLittleEndian(kHash, 0, 64).mod(L)

        // S * B = R + k * A
        val sB = mul(Point(BX, BY), s)
        val kA = mul(aPoint, k)
        val rPlusKa = add(rPoint, kA)

        return sB.x.equals(rPlusKa.x) && sB.y.equals(rPlusKa.y)
    }
}
