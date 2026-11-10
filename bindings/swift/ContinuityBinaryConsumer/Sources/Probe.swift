// SPDX-License-Identifier: Apache-2.0 OR MIT
import Foundation
import QPeriaptContinuity
import Darwin
#if canImport(UIKit)
import UIKit
#endif

struct ProbeFailure: Error { let message: String }
func requireCode(_ code: Int32, _ body: () throws -> Void) throws {
    do { try body() }
    catch let error as ContinuityFailure {
        guard error.code == code else { throw error }
        return
    }
    throw ProbeFailure(message: "expected native refusal \(code)")
}
// Execute the public wrapper and the packaged native owner; no source-library
// override, prebuilt identity or registry fixture is available to this consumer.
func probe() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false,
                                           attributes: [.posixPermissions: 0o700])
    let result = Result {
        guard let resolved = realpath(directory.path, nil) else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
        }
        let path = String(cString: resolved) + "/uncreated"; free(resolved)
        let owner = try ContinuityDevice.prepare(path: path)
        let operation = Result {
            try owner.cancel()
            try requireCode(302) { try owner.finishOpen() }
            guard !FileManager.default.fileExists(atPath: path) else {
                throw ProbeFailure(message: "cancelled open created state")
            }
        }
        do { try owner.close() } catch {
            throw ProbeFailure(message: "close failed: \(error); operation: \(operation)")
        }
        try operation.get()
        try requireCode(2) { _ = try owner.nextPublication() }
    }
    do { try FileManager.default.removeItem(at: directory) } catch {
        throw ProbeFailure(message: "owned directory cleanup failed: \(error); operation: \(result)")
    }
    try result.get()
    print("CONTINUITY_BINARY_CONSUMER_PASS cancelled=302 closed=2 created_state=false")
}
func executeProbe() {
    do { try probe(); exit(0) }
    catch { fputs("CONTINUITY_BINARY_CONSUMER_FAIL \(error)\n", stderr); exit(1) }
}
#if canImport(UIKit)
@main @MainActor
final class AppDelegate: UIResponder, UIApplicationDelegate {
    func application(_ application: UIApplication, configurationForConnecting session: UISceneSession,
                     options: UIScene.ConnectionOptions) -> UISceneConfiguration {
        let configuration = UISceneConfiguration(name: "Consumer", sessionRole: session.role)
        configuration.delegateClass = SceneDelegate.self
        return configuration
    }
}
@MainActor
final class SceneDelegate: UIResponder, UIWindowSceneDelegate {
    var window: UIWindow?
    private var started = false
    func scene(_ scene: UIScene, willConnectTo session: UISceneSession, options: UIScene.ConnectionOptions) {
        guard let scene = scene as? UIWindowScene else { exit(1) }
        let window = UIWindow(windowScene: scene)
        window.rootViewController = UIViewController(); window.makeKeyAndVisible(); self.window = window
    }
    func sceneDidBecomeActive(_ scene: UIScene) {
        guard !started else { return }; started = true
        executeProbe()
    }
}
#else
@main enum Main { static func main() { executeProbe() } }
#endif
