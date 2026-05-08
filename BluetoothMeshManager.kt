package com.bluechat.bluetooth

import android.Manifest
import android.annotation.SuppressLint
import android.bluetooth.*
import android.bluetooth.le.*
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.ParcelUuid
import android.util.Log
import androidx.core.content.ContextCompat
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * BluetoothMeshManager handles BLE scanning, advertising, and GATT communication.
 *
 * Architecture:
 * - Advertises as a GATT server with BlueChat service UUID
 * - Scans for other BlueChat devices
 * - Maintains GATT connections to nearby peers
 * - Routes messages through the mesh (TTL-based relay)
 */
@SuppressLint("MissingPermission")
class BluetoothMeshManager(private val context: Context) {

    companion object {
        private const val TAG = "BluetoothMesh"

        // Service UUID - unique to BlueChat
        val SERVICE_UUID: UUID = UUID.fromString("6E400001-B5A3-F393-E0A9-E50E24DCCA9E")
        val CHAR_MESSAGE_UUID: UUID = UUID.fromString("6E400002-B5A3-F393-E0A9-E50E24DCCA9E")
        val CHAR_ANNOUNCE_UUID: UUID = UUID.fromString("6E400003-B5A3-F393-E0A9-E50E24DCCA9E")
        val CCCD_UUID: UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")

        private const val MAX_CHUNK_SIZE = 512   // BLE MTU
        private const val SCAN_PERIOD_MS = 15000L
        private const val ADVERTISE_INTERVAL = AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY
        private const val MAX_CONNECTIONS = 7    // BLE practical limit
    }

    private val bluetoothManager = context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
    private val bluetoothAdapter = bluetoothManager.adapter
    private val bleScanner: BluetoothLeScanner? get() = bluetoothAdapter?.bluetoothLeScanner
    private val bleAdvertiser: BluetoothLeAdvertiser? get() = bluetoothAdapter?.bluetoothLeAdvertiser

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    // Connected GATT clients (we are server)
    private val connectedClients = ConcurrentHashMap<String, BluetoothDevice>()
    // Our GATT connections (we are client)
    private val gattConnections = ConcurrentHashMap<String, BluetoothGatt>()
    // Message characteristics of connected servers
    private val serverMessageChars = ConcurrentHashMap<String, BluetoothGattCharacteristic>()
    // Discovered but not yet connected peers
    private val discoveredDevices = ConcurrentHashMap<String, BluetoothDevice>()

    // ─── State Flows ─────────────────────────────────────────────────────────

    private val _incomingMessages = MutableSharedFlow<Pair<String, ByteArray>>(replay = 0)
    val incomingMessages: SharedFlow<Pair<String, ByteArray>> = _incomingMessages

    private val _peerConnected = MutableSharedFlow<String>(replay = 0)
    val peerConnected: SharedFlow<String> = _peerConnected

    private val _peerDisconnected = MutableSharedFlow<String>(replay = 0)
    val peerDisconnected: SharedFlow<String> = _peerDisconnected

    private val _scanResults = MutableStateFlow<List<BluetoothDevice>>(emptyList())
    val scanResults: StateFlow<List<BluetoothDevice>> = _scanResults

    private val _isScanning = MutableStateFlow(false)
    val isScanning: StateFlow<Boolean> = _isScanning

    private val _isAdvertising = MutableStateFlow(false)
    val isAdvertising: StateFlow<Boolean> = _isAdvertising

    private val _connectedPeersCount = MutableStateFlow(0)
    val connectedPeersCount: StateFlow<Int> = _connectedPeersCount

    // Message reassembly buffers
    private val messageBuffers = ConcurrentHashMap<String, StringBuilder>()

    // ─── GATT Server ─────────────────────────────────────────────────────────

    private var gattServer: BluetoothGattServer? = null

    private val gattServerCallback = object : BluetoothGattServerCallback() {
        override fun onConnectionStateChange(device: BluetoothDevice, status: Int, newState: Int) {
            when (newState) {
                BluetoothProfile.STATE_CONNECTED -> {
                    Log.d(TAG, "Client connected: ${device.address}")
                    connectedClients[device.address] = device
                    _connectedPeersCount.value = getTotalConnections()
                    scope.launch { _peerConnected.emit(device.address) }
                }
                BluetoothProfile.STATE_DISCONNECTED -> {
                    Log.d(TAG, "Client disconnected: ${device.address}")
                    connectedClients.remove(device.address)
                    _connectedPeersCount.value = getTotalConnections()
                    scope.launch { _peerDisconnected.emit(device.address) }
                }
            }
        }

        override fun onCharacteristicWriteRequest(
            device: BluetoothDevice,
            requestId: Int,
            characteristic: BluetoothGattCharacteristic,
            preparedWrite: Boolean,
            responseNeeded: Boolean,
            offset: Int,
            value: ByteArray
        ) {
            gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, null)

            when (characteristic.uuid) {
                CHAR_MESSAGE_UUID -> {
                    scope.launch {
                        _incomingMessages.emit(Pair(device.address, value))
                    }
                }
                CHAR_ANNOUNCE_UUID -> {
                    scope.launch {
                        _incomingMessages.emit(Pair(device.address, value))
                    }
                }
            }
        }

        override fun onDescriptorWriteRequest(
            device: BluetoothDevice,
            requestId: Int,
            descriptor: BluetoothGattDescriptor,
            preparedWrite: Boolean,
            responseNeeded: Boolean,
            offset: Int,
            value: ByteArray
        ) {
            gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, null)
        }

        override fun onMtuChanged(device: BluetoothDevice, mtu: Int) {
            Log.d(TAG, "MTU changed for ${device.address}: $mtu")
        }
    }

    fun startGattServer() {
        if (!hasBluetoothPermissions()) return

        val service = BluetoothGattService(SERVICE_UUID, BluetoothGattService.SERVICE_TYPE_PRIMARY)

        val msgChar = BluetoothGattCharacteristic(
            CHAR_MESSAGE_UUID,
            BluetoothGattCharacteristic.PROPERTY_WRITE or
                    BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE or
                    BluetoothGattCharacteristic.PROPERTY_NOTIFY,
            BluetoothGattCharacteristic.PERMISSION_WRITE
        )
        val cccd = BluetoothGattDescriptor(
            CCCD_UUID,
            BluetoothGattDescriptor.PERMISSION_READ or BluetoothGattDescriptor.PERMISSION_WRITE
        )
        msgChar.addDescriptor(cccd)

        val announceChar = BluetoothGattCharacteristic(
            CHAR_ANNOUNCE_UUID,
            BluetoothGattCharacteristic.PROPERTY_WRITE or
                    BluetoothGattCharacteristic.PROPERTY_NOTIFY,
            BluetoothGattCharacteristic.PERMISSION_WRITE
        )

        service.addCharacteristic(msgChar)
        service.addCharacteristic(announceChar)

        gattServer = bluetoothManager.openGattServer(context, gattServerCallback)
        gattServer?.addService(service)
        Log.d(TAG, "GATT server started")
    }

    // ─── BLE Advertising ─────────────────────────────────────────────────────

    private val advertiseCallback = object : AdvertiseCallback() {
        override fun onStartSuccess(settingsInEffect: AdvertiseSettings) {
            _isAdvertising.value = true
            Log.d(TAG, "BLE advertising started")
        }
        override fun onStartFailure(errorCode: Int) {
            _isAdvertising.value = false
            Log.e(TAG, "BLE advertising failed: $errorCode")
        }
    }

    fun startAdvertising(deviceName: String) {
        if (!hasBluetoothPermissions()) return

        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(ADVERTISE_INTERVAL)
            .setConnectable(true)
            .setTimeout(0)
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_MEDIUM)
            .build()

        val data = AdvertiseData.Builder()
            .setIncludeDeviceName(false)
            .addServiceUuid(ParcelUuid(SERVICE_UUID))
            .build()

        val scanResponse = AdvertiseData.Builder()
            .setIncludeDeviceName(true)
            .build()

        try {
            bluetoothAdapter?.name = "BC:${deviceName.take(10)}"
        } catch (e: Exception) {
            Log.w(TAG, "Could not set device name")
        }

        bleAdvertiser?.startAdvertising(settings, data, scanResponse, advertiseCallback)
    }

    fun stopAdvertising() {
        bleAdvertiser?.stopAdvertising(advertiseCallback)
        _isAdvertising.value = false
    }

    // ─── BLE Scanning ────────────────────────────────────────────────────────

    private val scanCallback = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult) {
            val device = result.device
            if (!discoveredDevices.containsKey(device.address)) {
                discoveredDevices[device.address] = device
                _scanResults.value = discoveredDevices.values.toList()
                connectToDevice(device)
            }
        }

        override fun onScanFailed(errorCode: Int) {
            Log.e(TAG, "BLE scan failed: $errorCode")
            _isScanning.value = false
        }
    }

    fun startScanning() {
        if (!hasBluetoothPermissions()) return

        val filter = ScanFilter.Builder()
            .setServiceUuid(ParcelUuid(SERVICE_UUID))
            .build()

        val settings = ScanSettings.Builder()
            .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
            .setCallbackType(ScanSettings.CALLBACK_TYPE_ALL_MATCHES)
            .setMatchMode(ScanSettings.MATCH_MODE_AGGRESSIVE)
            .build()

        bleScanner?.startScan(listOf(filter), settings, scanCallback)
        _isScanning.value = true

        // Restart scan periodically to catch new devices
        scope.launch {
            delay(SCAN_PERIOD_MS)
            if (_isScanning.value) {
                stopScanning()
                delay(1000)
                startScanning()
            }
        }
    }

    fun stopScanning() {
        bleScanner?.stopScan(scanCallback)
        _isScanning.value = false
    }

    // ─── GATT Client Connections ─────────────────────────────────────────────

    private val gattCallbacks = ConcurrentHashMap<String, BluetoothGattCallback>()

    fun connectToDevice(device: BluetoothDevice) {
        if (gattConnections.containsKey(device.address)) return
        if (getTotalConnections() >= MAX_CONNECTIONS) return

        val callback = object : BluetoothGattCallback() {
            override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
                when (newState) {
                    BluetoothProfile.STATE_CONNECTED -> {
                        Log.d(TAG, "GATT connected to ${device.address}")
                        gatt.requestMtu(512)
                        gatt.discoverServices()
                    }
                    BluetoothProfile.STATE_DISCONNECTED -> {
                        Log.d(TAG, "GATT disconnected from ${device.address}")
                        gattConnections.remove(device.address)
                        serverMessageChars.remove(device.address)
                        gattCallbacks.remove(device.address)
                        _connectedPeersCount.value = getTotalConnections()
                        scope.launch { _peerDisconnected.emit(device.address) }
                        gatt.close()
                    }
                }
            }

            override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
                if (status == BluetoothGatt.GATT_SUCCESS) {
                    val service = gatt.getService(SERVICE_UUID)
                    val msgChar = service?.getCharacteristic(CHAR_MESSAGE_UUID)
                    if (msgChar != null) {
                        serverMessageChars[device.address] = msgChar
                        gattConnections[device.address] = gatt
                        _connectedPeersCount.value = getTotalConnections()
                        scope.launch { _peerConnected.emit(device.address) }
                        Log.d(TAG, "Services discovered for ${device.address}")
                    }
                }
            }

            override fun onCharacteristicChanged(
                gatt: BluetoothGatt,
                characteristic: BluetoothGattCharacteristic,
                value: ByteArray
            ) {
                scope.launch {
                    _incomingMessages.emit(Pair(device.address, value))
                }
            }

            @Deprecated("Deprecated in Java")
            override fun onCharacteristicChanged(
                gatt: BluetoothGatt,
                characteristic: BluetoothGattCharacteristic
            ) {
                scope.launch {
                    _incomingMessages.emit(Pair(device.address, characteristic.value ?: return@launch))
                }
            }
        }

        gattCallbacks[device.address] = callback

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            device.connectGatt(context, false, callback, BluetoothDevice.TRANSPORT_LE)
        } else {
            device.connectGatt(context, false, callback)
        }
    }

    // ─── Sending Messages ─────────────────────────────────────────────────────

    fun sendMessage(targetAddress: String, data: ByteArray): Boolean {
        val gatt = gattConnections[targetAddress] ?: return false
        val char = serverMessageChars[targetAddress] ?: return false
        char.value = data
        return gatt.writeCharacteristic(char)
    }

    fun broadcastMessage(data: ByteArray) {
        // Send to all GATT clients (server role)
        val msgChar = gattServer?.getService(SERVICE_UUID)?.getCharacteristic(CHAR_MESSAGE_UUID)
        if (msgChar != null) {
            connectedClients.values.forEach { device ->
                msgChar.value = data
                gattServer?.notifyCharacteristicChanged(device, msgChar, false)
            }
        }

        // Also write to all connected GATT servers (client role)
        gattConnections.keys.forEach { address ->
            sendMessage(address, data)
        }
    }

    // ─── Helpers ─────────────────────────────────────────────────────────────

    fun getTotalConnections(): Int = connectedClients.size + gattConnections.size

    fun isBluetoothEnabled(): Boolean = bluetoothAdapter?.isEnabled == true

    fun hasBluetoothPermissions(): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            ContextCompat.checkSelfPermission(context, Manifest.permission.BLUETOOTH_SCAN) ==
                    PackageManager.PERMISSION_GRANTED &&
                    ContextCompat.checkSelfPermission(context, Manifest.permission.BLUETOOTH_CONNECT) ==
                    PackageManager.PERMISSION_GRANTED &&
                    ContextCompat.checkSelfPermission(context, Manifest.permission.BLUETOOTH_ADVERTISE) ==
                    PackageManager.PERMISSION_GRANTED
        } else {
            ContextCompat.checkSelfPermission(context, Manifest.permission.BLUETOOTH) ==
                    PackageManager.PERMISSION_GRANTED &&
                    ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_FINE_LOCATION) ==
                    PackageManager.PERMISSION_GRANTED
        }
    }

    fun getConnectedAddresses(): Set<String> =
        connectedClients.keys + gattConnections.keys

    fun disconnect(address: String) {
        gattConnections[address]?.disconnect()
    }

    fun stop() {
        stopScanning()
        stopAdvertising()
        gattConnections.values.forEach { it.disconnect() }
        gattConnections.clear()
        gattServer?.close()
        connectedClients.clear()
        scope.cancel()
    }
}
