package lantern.android

import android.net.ConnectivityManager
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Column
import androidx.compose.material3.Text
import androidx.compose.runtime.mutableStateOf
import app.cash.sqldelight.driver.android.AndroidSqliteDriver
import lantern.connectivity.Node
import lantern.connectivity.LocalGroupService
import lantern.persistence.LanternDatabase
import lantern.persistence.SqliteDeviceRepository
import lantern.ui.LanternApp
import java.net.Inet4Address
import java.net.InetAddress

class MainActivity : ComponentActivity() {
    private var node: Node? = null
    private var repository: SqliteDeviceRepository? = null
    private var localGroup: LocalGroupService? = null
    private val discoveryError = mutableStateOf("")

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val address = localAddress()
        if (address == null) {
            setContent { Text("Collega il dispositivo a una LAN Wi-Fi e riapri Lantern.") }
            return
        }
        try {
            val controller = createNode(address)
            node = controller
            val group = LocalGroupService(controller.identity, checkNotNull(repository))
            localGroup = group
            setContent {
                Column {
                    if (discoveryError.value.isNotEmpty()) Text(discoveryError.value)
                    LanternApp(controller, group)
                }
            }
        } catch (error: Exception) {
            runCatching { localGroup?.close() }.exceptionOrNull()?.let(error::addSuppressed)
            localGroup = null
            runCatching { node?.close() }.exceptionOrNull()?.let(error::addSuppressed)
            node = null
            runCatching { repository?.close() }.exceptionOrNull()?.let(error::addSuppressed)
            repository = null
            val message = if (error is IncompatibleAndroidIdentityException) {
                error.message.orEmpty()
            } else {
                "Avvio non riuscito: ${error.javaClass.simpleName}"
            }
            setContent { Text(message) }
        }
    }

    private fun localAddress(): InetAddress? {
        val manager = getSystemService(ConnectivityManager::class.java)
        return manager.getLinkProperties(manager.activeNetwork)?.linkAddresses
            ?.map { it.address }
            ?.firstOrNull { it is Inet4Address && it.isSiteLocalAddress }
    }

    private fun createNode(address: InetAddress): Node {
        val database = SqliteDeviceRepository(AndroidSqliteDriver(LanternDatabase.Schema, this, "lantern.db"))
        repository = database
        val discovery = AndroidDiscovery(this) { message ->
            runOnUiThread { discoveryError.value = message }
        }
        return Node(androidIdentity(), database, discovery, address)
    }

    // The PoC is foreground-only. Background execution remains a separate product increment.
    override fun onStop() {
        node?.stop()
        super.onStop()
    }

    override fun onDestroy() {
        try {
            try { localGroup?.close() } finally { node?.close() }
        } finally {
            repository?.close()
            node = null
            repository = null
            localGroup = null
            super.onDestroy()
        }
    }
}
