package lantern.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.ComposeUIViewController
import lantern.domain.ContentLimits
import lantern.persistence.IosDeviceRepository
import lantern.persistence.openIosRepository
import platform.UIKit.UIViewController

class IosPersistence private constructor(private val repository: IosDeviceRepository) {
    @Throws(Exception::class)
    fun name(): String = repository.name()

    @Throws(Exception::class)
    fun rename(value: String) {
        require(ContentLimits.isValidName(value)) { "Nome dispositivo non valido" }
        repository.rename(value)
    }
    fun close() = repository.close()

    companion object {
        fun open(databaseDirectory: String) = IosPersistence(openIosRepository(databaseDirectory))
    }
}

@Throws(Exception::class)
fun openIosPersistence(databaseDirectory: String): IosPersistence = IosPersistence.open(databaseDirectory)

/** Native Bonjour probe. This entry intentionally does not expose unimplemented messaging. */
class IosProbeState {
    var identityId by mutableStateOf("")
        private set
    var identityError by mutableStateOf("")
        private set
    var status by mutableStateOf("Scoperta Bonjour arrestata")
        private set
    var deviceName by mutableStateOf("")
        private set
    var persistenceError by mutableStateOf("")
        private set
    var devices by mutableStateOf(listOf<String>())
        private set
    fun updateStatus(value: String) { status = value }
    fun updateDevices(values: List<String>) { devices = values }
    fun updateIdentity(value: String) { identityId = value; identityError = "" }
    fun updateIdentityError(value: String) { identityError = value; identityId = "" }
    fun updateDeviceName(value: String) { deviceName = value; persistenceError = "" }
    fun updatePersistenceError(value: String) { persistenceError = value }
}
fun ProbeViewController(
    state: IosProbeState,
    start: () -> Unit,
    stop: () -> Unit,
    rename: (String) -> Unit,
): UIViewController = ComposeUIViewController {
    MaterialTheme {
        Surface(Modifier.fillMaxSize()) {
            Column(Modifier.padding(24.dp).verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(16.dp)) {
                Text("Lantern · iPhone", style = MaterialTheme.typography.headlineMedium)
                Text("Persistenza locale e verifica preliminare Bonjour")
                if (state.identityId.isNotEmpty()) Text("Identità persistente: ${state.identityId}")
                else Text(state.identityError.ifEmpty { "Apertura identità nel Keychain…" })
                var editedName by remember(state.deviceName) { mutableStateOf(state.deviceName) }
                OutlinedTextField(
                    value = editedName,
                    onValueChange = { editedName = it },
                    label = { Text("Nome dispositivo") },
                    singleLine = true,
                    enabled = state.deviceName.isNotEmpty(),
                )
                Button(
                    onClick = { rename(editedName) },
                    enabled = state.deviceName.isNotEmpty() &&
                        editedName != state.deviceName && ContentLimits.isValidName(editedName),
                ) { Text("Salva nome") }
                if (state.persistenceError.isNotEmpty()) Text(state.persistenceError, color = MaterialTheme.colorScheme.error)
                Text("Il trasporto TLS e l'associazione iOS non sono ancora implementati. La ricerca verifica soltanto la scoperta reale dei servizi LAN.")
                Row { Button(onClick = start, enabled = state.identityId.isNotEmpty()) { Text("Cerca nella LAN") }; TextButton(onClick = stop) { Text("Arresta") } }
                Text(state.status)
                state.devices.forEach { Text(it) }
            }
        }
    }
}
