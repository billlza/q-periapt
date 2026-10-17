// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt

import java.lang.reflect.Modifier
import java.net.URI
import java.nio.file.Files
import java.nio.file.Path
import javax.tools.Diagnostic
import javax.tools.DiagnosticCollector
import javax.tools.JavaFileObject
import javax.tools.SimpleJavaFileObject
import javax.tools.ToolProvider
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class QPeriaptJavaBoundaryTest {
    private fun compile(body: String): Pair<Boolean, List<String>> {
        val compiler = requireNotNull(ToolProvider.getSystemJavaCompiler())
        val diagnostics = DiagnosticCollector<JavaFileObject>()
        val source = object : SimpleJavaFileObject(URI.create("string:///Consumer.java"), JavaFileObject.Kind.SOURCE) {
            override fun getCharContent(ignoreEncodingErrors: Boolean) = body
        }
        val classpath = listOf(QPeriaptRuntime::class.java, Unit::class.java)
            .joinToString(System.getProperty("path.separator")) { Path.of(it.protectionDomain.codeSource.location.toURI()).toString() }
        val output = Files.createTempDirectory("qperiapt-java-boundary-")
        try {
            compiler.getStandardFileManager(diagnostics, null, null).use { files ->
                val success = compiler.getTask(null, files, diagnostics,
                    listOf("--release", "25", "-Xlint:all", "-Werror", "-cp", classpath, "-d", output.toString()),
                    null, listOf(source)).call()
                return success to diagnostics.diagnostics.filter { it.kind == Diagnostic.Kind.ERROR }.map { it.code }
            }
        } finally {
            // Only files created by this isolated compiler invocation.
            Files.walk(output).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach { Files.delete(it) } }
        }
    }

    @Test
    fun javaFactoryCallsCompileButRawOwnerConstructionDoesNot() {
        val allowed = compile("""
            import dev.qperiapt.*;
            final class Consumer {
              static QPeriaptRuntime open(byte[] p, byte[] s, byte[] r) {
                return QPeriaptRuntime.Companion.fromSignedPolicy(p, s, r, new byte[0], 32, 4);
              }
              static QPeriaptKey key(QPeriaptRuntime r) { return r.generateKey(); }
              static QPeriaptPersistentRuntime persistent(String path, byte[] p, byte[] s, byte[] r) {
                return QPeriaptPersistentRuntime.Companion.provision(path, p, s, r, 32, 4);
              }
              static QPeriaptPolicyRecoveryTrust trust(byte[] scope, byte[] initial, byte[] recovery) {
                return new QPeriaptPolicyRecoveryTrust(scope, initial, recovery);
              }
              static QPeriaptPolicyRecoveryRequest request(byte[] encoded) {
                return new QPeriaptPolicyRecoveryRequest(encoded);
              }
            }
        """.trimIndent())
        assertTrue(allowed.first, allowed.second.toString())
        val forbidden = compile("""
            import dev.qperiapt.*;
            final class Consumer {
              static Object forge() { return new QPeriaptRuntime(new SdkHandle(1L, null)); }
              static Object alias(QPeriaptRuntime r) { return new QPeriaptRuntime(r.getOwned${'$'}q_periapt_hybrid()); }
              static Object key() { return new QPeriaptKey(null); }
              static Object secret() { return new QPeriaptSecret(null); }
              static Object persistent(QPeriaptRuntime r) { return new QPeriaptPersistentRuntime(r); }
              static Object recovered(QPeriaptPersistentRuntime r) { return new QPeriaptPolicyRecoveryResult.Applied(r); }
              static Object reopened(QPeriaptPersistentRuntime r) {
                return new QPeriaptPolicyRecoveryReopen(r, QPeriaptPolicyRecoveryDisposition.APPLIED);
              }
            }
        """.trimIndent())
        assertFalse(forbidden.first)
        assertTrue(forbidden.second.isNotEmpty())
        assertTrue(forbidden.second.all { it.startsWith("compiler.err.report.access") || it.startsWith("compiler.err.cant.resolve") },
            forbidden.second.toString())
    }

    @Test
    fun ownerConstructorsArePrivateAndInternalAccessorsAreSynthetic() {
        val owners = listOf(QPeriaptRuntime::class.java, QPeriaptPersistentRuntime::class.java, QPeriaptKey::class.java, QPeriaptSecret::class.java,
            QPeriaptDerivedKey::class.java, QPeriaptPolicyUpdate::class.java, QPeriaptPolicyStates::class.java,
            QPeriaptSDKEncapsulation::class.java, SdkHandle::class.java,
            QPeriaptPolicyRecoveryResult.Applied::class.java, QPeriaptPolicyRecoveryReopen::class.java)
        for (owner in owners) {
            assertTrue(owner.declaredConstructors.filterNot { it.isSynthetic }.all { Modifier.isPrivate(it.modifiers) }, owner.name)
        }
        for (owner in listOf(QPeriaptRuntime::class.java, QPeriaptKey::class.java)) {
            assertTrue(owner.declaredMethods.filter { it.name.startsWith("getOwned") }.all { it.isSynthetic })
        }
        val shared = Class.forName("dev.qperiapt.QPeriaptSDKKt").declaredMethods.single { it.name == "submitSdkOperation" }
        assertTrue(shared.isSynthetic)
        for (name in listOf("withHandle", "withParentHandle")) {
            assertTrue(SdkHandle::class.java.declaredMethods.single { it.name == name }.isSynthetic)
        }
    }
}
