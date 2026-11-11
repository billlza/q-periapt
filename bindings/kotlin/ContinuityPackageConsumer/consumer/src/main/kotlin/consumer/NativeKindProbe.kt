// SPDX-License-Identifier: Apache-2.0 OR MIT
package consumer

import dev.qperiapt.continuity.WitnessCarrier
import java.lang.foreign.Arena
import java.lang.foreign.FunctionDescriptor
import java.lang.foreign.Linker
import java.lang.foreign.MemoryLayout
import java.lang.foreign.MemorySegment
import java.lang.foreign.SymbolLookup
import java.lang.foreign.ValueLayout.ADDRESS
import java.lang.foreign.ValueLayout.JAVA_BYTE
import java.lang.foreign.ValueLayout.JAVA_INT
import java.lang.foreign.ValueLayout.JAVA_LONG
import java.lang.foreign.ValueLayout.JAVA_SHORT
import java.nio.file.Path

/** Deliberate raw C negative control in the test executable only. The SDK JAR
 * exposes neither handles nor an operational/recovery conversion. */
internal fun checkNativeKindSeparation(path: String, carrier: WitnessCarrier) = Arena.ofConfined().use { arena ->
    val lookup = SymbolLookup.libraryLookup(Path.of(System.getProperty("qperiapt.continuity.lib")), arena)
    val linker = Linker.nativeLinker()
    val error = arena.allocate(524, 4)
    fun invoke(name: String, layouts: List<MemoryLayout>, args: List<Any>, expected: Int) {
        error.fill(0)
        val function = linker.downcallHandle(lookup.findOrThrow(name),
            FunctionDescriptor.of(JAVA_INT, *(layouts + ADDRESS).toTypedArray()))
        val code = function.invokeWithArguments(args + error) as Int
        val size = error.get(JAVA_INT, 4); val truncated = error.get(JAVA_INT, 8)
        check(code == expected && error.get(JAVA_INT, 0) == code && size in 0..512 && truncated in 0..1 &&
            (if (code == 0) size == 0 && truncated == 0 else size > 0)) { "native kind negative control" }
    }
    val input = path.toByteArray(); val encoded = arena.allocateFrom(JAVA_BYTE, *input)
    val witness = when (carrier) {
        WitnessCarrier.Local -> MemorySegment.NULL
        else -> {
            val address: String; val timeout: Int
            when (carrier) {
                is WitnessCarrier.SignedTCP -> { address = carrier.address; timeout = carrier.timeoutMilliseconds }
                is WitnessCarrier.MutualTLS -> { address = carrier.address; timeout = carrier.timeoutMilliseconds }
                WitnessCarrier.Local -> error("local carrier handled")
            }
            val text = address.toByteArray()
            arena.allocate(24, 8).also {
                it.set(ADDRESS, 0, arena.allocateFrom(JAVA_BYTE, *text))
                it.set(JAVA_LONG, 8, text.size.toLong()); it.set(JAVA_INT, 16, timeout)
            }
        }
    }
    for (kind in 1..2) {
        val options = arena.allocate(24, 8)
        options.set(JAVA_INT, 0, kind); options.set(JAVA_INT, 4, if (kind == 1) 1 else 0)
        options.set(JAVA_INT, 8, when (carrier) {
            WitnessCarrier.Local -> 0
            is WitnessCarrier.SignedTCP -> 1
            is WitnessCarrier.MutualTLS -> 2
        })
        options.set(ADDRESS, 16, witness)
        val output = arena.allocate(JAVA_LONG)
        invoke("qpc_owner_v1_prepare_open", listOf(ADDRESS, JAVA_LONG, ADDRESS, ADDRESS),
            listOf(encoded, input.size.toLong(), options, output), 0)
        val handle = output.get(JAVA_LONG, 0); check(handle != 0L)
        AutoCloseable { invoke("qpc_owner_v1_close", listOf(JAVA_LONG), listOf(handle), 0) }.use {
            invoke("qpc_owner_v1_finish_open", listOf(JAVA_LONG), listOf(handle), 0)
            if (kind == 1) {
                invoke("qpc_recovery_v1_begin", listOf(JAVA_LONG, ADDRESS), listOf(handle, arena.allocate(200, 8)), 6)
            } else {
                val address = "127.0.0.1:0".toByteArray(); val port = arena.allocate(JAVA_SHORT)
                port.set(JAVA_SHORT, 0, 99)
                invoke("qpc_owner_v1_listen", listOf(JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS),
                    listOf(handle, arena.allocateFrom(JAVA_BYTE, *address), address.size.toLong(), port), 6)
                check(port.get(JAVA_SHORT, 0) == 0.toShort()) { "cleanup owner acquired a listener" }
            }
        }
    }
}
