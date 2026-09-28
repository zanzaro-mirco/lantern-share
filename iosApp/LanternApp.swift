import SwiftUI
import Network
import LanternUI
import LanternIdentity

final class BonjourProbe: ObservableObject {
    let state = IosProbeState()
    private var browser: NWBrowser?
    private var identity: AppleIdentity?
    private var generation = 0

    init() {
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let result = Result { try AppleIdentityStore().open() }
            DispatchQueue.main.async {
                guard let self else { return }
                switch result {
                case .success(let identity):
                    self.identity = identity
                    self.state.updateIdentity(value: identity.id)
                case .failure(let error):
                    self.state.updateIdentityError(value: error.localizedDescription)
                }
            }
        }
    }

    func start() {
        guard identity != nil else { return }
        stop()
        let currentGeneration = generation
        let parameters = NWParameters.tcp
        parameters.includePeerToPeer = false
        let browser = NWBrowser(for: .bonjour(type: "_lantern._tcp", domain: "local."), using: parameters)
        self.browser = browser
        browser.stateUpdateHandler = { [weak self] value in
            DispatchQueue.main.async {
                guard self?.generation == currentGeneration else { return }
                self?.state.updateStatus(value: "Bonjour: \(value)")
            }
        }
        browser.browseResultsChangedHandler = { [weak self] results, _ in
            let names = results.map { String(describing: $0.endpoint) }.sorted()
            DispatchQueue.main.async {
                guard self?.generation == currentGeneration else { return }
                self?.state.updateDevices(values: names)
            }
        }
        browser.start(queue: .main)
    }
    func stop() {
        generation += 1
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
