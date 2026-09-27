package lantern.desktop

import androidx.compose.ui.window.Window
import androidx.compose.ui.window.application
import lantern.connectivity.Identity
import lantern.connectivity.LanDiscovery
import lantern.connectivity.MacKeychainIdentityStore
import lantern.connectivity.Node
import lantern.connectivity.open
import lantern.persistence.openDesktopRepository
import lantern.ui.LanternApp
import java.net.Inet4Address
import java.net.InetAddress
import java.net.NetworkInterface
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.nio.file.StandardOpenOption
import javax.swing.JOptionPane
import javax.swing.JPasswordField

fun main() {
    val address = selectAddress() ?: return
    val directory = Paths.get(System.getProperty(
        "lantern.home", Paths.get(System.getProperty("user.home"), ".lantern").toString(),
    ))
    Files.createDirectories(directory)
    FileChannel.open(directory.resolve("instance.lock"), StandardOpenOption.CREATE, StandardOpenOption.WRITE).use { channel ->
        val lock = channel.tryLock()
        if (lock == null) {
            JOptionPane.showMessageDialog(null, "Questa identità è già in uso")
            return
        }
        lock.use {
            val identity = unlockIdentity(directory) ?: return
            openDesktopRepository(directory.resolve("lantern.db")).use { repository ->
                Node(identity, repository, LanDiscovery(address), address).use { node ->
                    application(exitProcessOnExit = false) {
                        Window(onCloseRequest = ::exitApplication, title = "Lantern · LAN") {
                            LanternApp(node)
                        }
                    }
                }
            }
        }
    }
}

private fun selectAddress(): InetAddress? {
    System.getProperty("lantern.bind")?.let { return InetAddress.getByName(it) }
    val interfaces = NetworkInterface.getNetworkInterfaces().toList()
        .filter { it.isUp && !it.isLoopback }
        .flatMap { network ->
            network.inetAddresses.toList()
                .filter { it is Inet4Address && it.isSiteLocalAddress }
                .map { network.name to it }
        }
    if (interfaces.isEmpty()) {
        JOptionPane.showMessageDialog(null, "Nessuna interfaccia LAN IPv4 attiva")
        return null
    }
    val choices = interfaces.map { "${it.first}: ${it.second.hostAddress}" }.toTypedArray()
    val selected = JOptionPane.showInputDialog(
        null, "Interfaccia LAN da utilizzare", "Lantern", JOptionPane.QUESTION_MESSAGE,
        null, choices, choices.first(),
    ) ?: return null
    return interfaces[choices.indexOf(selected)].second
}

private fun unlockIdentity(directory: Path): Identity? = try {
    if (System.getProperty("os.name").startsWith("Mac", ignoreCase = true)) {
        MacKeychainIdentityStore().open(directory) {
            askPassword("Importa l'identità esistente nel Portachiavi: inserisci la passphrase PKCS#12")
        }
    } else {
        val path = directory.resolve("identity.p12")
        check(!Files.exists(directory.resolve("mac-identity.ref")) || Files.exists(path)) {
            "Questo profilo usa il Portachiavi Mac: la cartella non contiene la chiave privata"
        }
        val prompt = if (Files.exists(path)) "Sblocca identità" else
            "Crea passphrase identità (almeno 12 caratteri). Conservala: non è recuperabile."
        askPassword(prompt)?.let { password ->
            try { Identity.open(path, password) } finally { password.fill('\u0000') }
        }
    }
} catch (error: Exception) {
    JOptionPane.showMessageDialog(null, "Impossibile aprire l'identità: ${error.message ?: error.javaClass.simpleName}")
    null
}

private fun askPassword(prompt: String): CharArray? {
    val field = JPasswordField(24)
    val choice = JOptionPane.showConfirmDialog(null, arrayOf(prompt, field), "Lantern", JOptionPane.OK_CANCEL_OPTION)
    if (choice != JOptionPane.OK_OPTION) {
        field.text = ""
        return null
    }
    val password = field.password
    field.text = ""
    return password
}
