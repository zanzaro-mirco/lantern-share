import SwiftUI
import LanternUI
struct ComposeScreen: UIViewControllerRepresentable {
    let probe: BonjourProbe
    func makeUIViewController(context: Context) -> UIViewController {
        IosEntryKt.ProbeViewController(
            state: probe.state,
            start: { probe.start() },
            stop: { probe.stop() },
            rename: { probe.rename($0) },
            pair: { probe.pair($0) },
            confirm: { probe.confirm() },
            reject: { probe.reject() }
        )
    }
    func updateUIViewController(_ controller: UIViewController, context: Context) {}
}
@main struct LanternApp: App {
    @StateObject private var probe = BonjourProbe()
    @Environment(\.scenePhase) private var scenePhase
    var body: some Scene {
        WindowGroup {
            ComposeScreen(probe: probe).ignoresSafeArea(.keyboard)
                .onChange(of: scenePhase) { phase in if phase != .active { probe.stop() } }
        }
    }
}
