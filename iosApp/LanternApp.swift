import SwiftUI
import Network
import LanternUI

final class BonjourProbe: ObservableObject {
    let state = IosProbeState()
    private var browser: NWBrowser?
    func start() {
        stop()
        let parameters = NWParameters.tcp
        parameters.includePeerToPeer = false
        let browser = NWBrowser(for: .bonjour(type: "_lantern._tcp", domain: "local."), using: parameters)
        self.browser = browser
        browser.stateUpdateHandler = { [weak self] value in
            DispatchQueue.main.async {
                self?.state.updateStatus(value: "Bonjour: \(value)")
            }
        }
        browser.browseResultsChangedHandler = { [weak self] results, _ in
            let names = results.map { String(describing: $0.endpoint) }.sorted()
            DispatchQueue.main.async { self?.state.updateDevices(values: names) }
        }
        browser.start(queue: .main)
    }
    func stop() {
        browser?.cancel(); browser = nil
        state.updateDevices(values: [])
        state.updateStatus(value: "Scoperta Bonjour arrestata")
    }
}
struct ComposeScreen: UIViewControllerRepresentable {
    let probe: BonjourProbe
    func makeUIViewController(context: Context) -> UIViewController {
        IosEntryKt.ProbeViewController(state: probe.state, start: { probe.start() }, stop: { probe.stop() })
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
