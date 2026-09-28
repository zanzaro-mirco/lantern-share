import SwiftUI
import Network
import LanternUI
import LanternIdentity

final class BonjourProbe: ObservableObject {
    let state = IosProbeState()
    private var browser: NWBrowser?
    private var identity: AppleIdentity?
    private var persistence: IosPersistence?
    private var generation = 0

    init() {
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let identityResult = Result { try AppleIdentityStore().open() }
            let persistenceResult: Result<(IosPersistence, String), Error> = Result {
                let directory = try FileManager.default.url(
                    for: .applicationSupportDirectory,
                    in: .userDomainMask,
                    appropriateFor: nil,
                    create: true
                ).appendingPathComponent("Lantern", isDirectory: true)
                try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
                let persistence = try IosEntryKt.openIosPersistence(databaseDirectory: directory.path)
                do {
                    return (persistence, try persistence.name())
                } catch {
                    persistence.close()
                    throw error
                }
            }
            DispatchQueue.main.async {
                guard let self else {
                    if case .success(let (persistence, _)) = persistenceResult { persistence.close() }
                    return
                }
                switch identityResult {
                case .success(let identity):
                    self.identity = identity
                    self.state.updateIdentity(value: identity.id)
                case .failure(let error):
                    self.state.updateIdentityError(value: error.localizedDescription)
                }
                switch persistenceResult {
                case .success(let (persistence, deviceName)):
                    self.persistence = persistence
                    self.state.updateDeviceName(value: deviceName)
                case .failure(let error):
                    self.state.updatePersistenceError(value: error.localizedDescription)
                }
            }
        }
    }

    deinit {
        persistence?.close()
    }

    func rename(_ value: String) {
        guard let persistence else { return }
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            do {
                try persistence.rename(value: value)
                DispatchQueue.main.async { self?.state.updateDeviceName(value: value) }
            } catch {
                DispatchQueue.main.async { self?.state.updatePersistenceError(value: error.localizedDescription) }
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
        IosEntryKt.ProbeViewController(
            state: probe.state,
            start: { probe.start() },
            stop: { probe.stop() },
            rename: { probe.rename($0) }
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
