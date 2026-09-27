package lantern.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.ComposeUIViewController
import platform.UIKit.UIViewController

/** Native Bonjour probe. This entry intentionally does not expose unimplemented messaging. */
class IosProbeState {
    var status by mutableStateOf("Scoperta Bonjour arrestata")
        private set
    var devices by mutableStateOf(listOf<String>())
        private set
    fun updateStatus(value: String) { status = value }
    fun updateDevices(values: List<String>) { devices = values }
}
fun ProbeViewController(state: IosProbeState, start: () -> Unit, stop: () -> Unit): UIViewController = ComposeUIViewController {
    MaterialTheme {
        Surface(Modifier.fillMaxSize()) {
            Column(Modifier.padding(24.dp).verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(16.dp)) {
                Text("Lantern · iPhone", style = MaterialTheme.typography.headlineMedium)
                Text("Verifica preliminare Bonjour")
                Text("Il trasporto TLS e l'associazione iOS non sono ancora implementati. Questa schermata verifica soltanto la scoperta reale dei servizi LAN.")
                Row { Button(onClick = start) { Text("Cerca nella LAN") }; TextButton(onClick = stop) { Text("Arresta") } }
                Text(state.status)
                state.devices.forEach { Text(it) }
            }
        }
    }
}
