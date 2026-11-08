// SPDX-License-Identifier: AGPL-3.0-only
package me.him188.ani.app.domain.mediasource.lanerc.core

/** Bounded protobuf wire decoder for the reconstructed messages, not a general protobuf runtime. */
internal object LanercWire {
    class Outer(val code: Int, val encrypted: Boolean, val data: ByteArray)
    private class Field(val number: Int, val type: Int, val scalar: Long = 0, val bytes: ByteArray = byteArrayOf())

    private fun fields(input: ByteArray): Sequence<Field> = sequence {
        require(input.size <= LanercProtocol.MAX_BYTES) { "Protobuf size limit" }
        var position = 0
        fun varint(): Long {
            var value = 0L
            for (i in 0..9) {
                require(position < input.size) { "Truncated varint" }
                val b = input[position++].toInt() and 255
                require(i != 9 || b <= 1) { "Varint overflow" }
                value = value or ((b and 127).toLong() shl (7 * i))
                if (b and 128 == 0) return value
            }
            error("Varint overflow")
        }
        fun bytes(count: Long): ByteArray {
            require(count >= 0 && count <= input.size - position) { "Truncated field" }
            val result = input.copyOfRange(position, position + count.toInt())
            position += count.toInt()
            return result
        }
        while (position < input.size) {
                val tag = varint()
                val number = tag ushr 3
                require(number in 1..0x1fffffffL) { "Invalid field number" }
                val type = (tag and 7).toInt()
                yield(when (type) {
                    0 -> Field(number.toInt(), type, scalar = varint())
                    1 -> Field(number.toInt(), type, bytes = bytes(8))
                    2 -> Field(number.toInt(), type, bytes = bytes(varint()))
                    5 -> Field(number.toInt(), type, bytes = bytes(4))
                    else -> error("Unsupported wire type")
                })
        }
    }

    fun response(input: ByteArray): Outer {
        var code = 0
        var encrypted = false
        var data = byteArrayOf()
        for (field in fields(input)) {
            when {
                field.number == 1 && field.type == 0 -> code = field.scalar.toInt()
                field.number == 2 && field.type == 2 -> field.bytes.decodeToString(throwOnInvalidSequence = true)
                field.number == 3 && field.type == 0 -> encrypted = field.scalar != 0L
                field.number == 4 && field.type == 2 -> data = field.bytes
            }
        }
        return Outer(code, encrypted, data)
    }

    fun playUrl(input: ByteArray): String {
        var url = ""
        for (field in fields(input)) {
            if (field.number == 1 && field.type == 2) url = field.bytes.decodeToString(throwOnInvalidSequence = true)
        }
        return url
    }
}
