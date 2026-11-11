// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt

import java.lang.foreign.Arena
import java.lang.foreign.FunctionDescriptor
import java.lang.foreign.Linker
import java.lang.foreign.SymbolLookup
import java.nio.file.Files
import java.nio.file.Path

/** One explicit library lookup shared by the legacy and owned ABI 2 surfaces. */
internal object QPeriaptNative {
    private val linker = Linker.nativeLinker()
    private val lookup: SymbolLookup = run {
        val explicit = System.getProperty("qperiapt.lib")
            ?: error("qperiapt.lib must be set to an absolute q-periapt native library path")
        val path = Path.of(explicit)
        require(path.isAbsolute) { "qperiapt.lib must be an absolute path: $explicit" }
        require(Files.isRegularFile(path)) { "qperiapt.lib does not name a regular file: $explicit" }
        SymbolLookup.libraryLookup(path, Arena.global())
    }

    fun handle(name: String, descriptor: FunctionDescriptor) =
        linker.downcallHandle(lookup.findOrThrow(name), descriptor)
}
