/*
 * FreeOTP
 *
 * Authors: Nathaniel McCallum <npmccallum@redhat.com>
 *
 * Copyright (C) 2013  Nathaniel McCallum, Red Hat
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Portions Copyright 2009 ZXing authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.fedorahosted.freeotp.ui

import android.Manifest
import android.annotation.SuppressLint
import android.app.Activity
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.DialogInterface
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.ParcelUuid
import android.util.Log
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.view.WindowManager
import android.widget.ImageButton
import android.widget.SearchView
import android.widget.Toast
import androidx.activity.viewModels
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.app.AppCompatDelegate
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.GridLayoutManager
import androidx.recyclerview.widget.ItemTouchHelper
import androidx.recyclerview.widget.RecyclerView.AdapterDataObserver
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.snackbar.Snackbar
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.launch
import org.fedorahosted.freeotp.R
import org.fedorahosted.freeotp.data.MigrationUtil
import org.fedorahosted.freeotp.data.OtpTokenDatabase
import org.fedorahosted.freeotp.data.OtpTokenFactory
import org.fedorahosted.freeotp.data.legacy.ImportExportUtil
import org.fedorahosted.freeotp.databinding.MainBinding
import org.fedorahosted.freeotp.util.Settings
import java.text.DateFormat
import java.text.SimpleDateFormat
import java.util.*
import javax.inject.Inject
import kotlin.math.max
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import androidx.recyclerview.widget.SimpleItemAnimator
import timber.log.Timber

// TODO MRN Performing a read or write operation

private const val ENABLE_BLUETOOTH_REQUEST_CODE = 1
private const val RUNTIME_PERMISSION_REQUEST_CODE = 2
private const val BETTER_TOTP_UUID = "17fce299-6810-4ddd-b809-ac46c9100f51"

@SuppressLint("LogNotTimber", "MissingPermission")
@AndroidEntryPoint
class MainActivity : AppCompatActivity() {
    @Inject lateinit var importFromUtil: ImportExportUtil
    @Inject lateinit var settings: Settings
    @Inject lateinit var tokenMigrationUtil: MigrationUtil
    @Inject lateinit var otpTokenDatabase: OtpTokenDatabase
    @Inject lateinit var tokenListAdapter: TokenListAdapter

    private val viewModel: MainViewModel by viewModels()
    private lateinit var binding: MainBinding
    private var searchQuery = ""
    private var menu: Menu? = null
    private var lastSessionEndTimestamp = 0L;

    private val tokenListObserver: AdapterDataObserver = object: AdapterDataObserver() {
        override fun onItemRangeInserted(positionStart: Int, itemCount: Int) {
            super.onItemRangeInserted(positionStart, itemCount)
            binding.tokenList.scrollToPosition(positionStart)
        }
    }

    private val dateFormatter : DateFormat = SimpleDateFormat("yyyyMMdd_HHmm")

    // Bluetooth Low Energy related:
    private val bleScanner by lazy {
        bluetoothAdapter.bluetoothLeScanner
    }
    private val bluetoothAdapter: BluetoothAdapter by lazy {
        val bluetoothManager = getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
        bluetoothManager.adapter
    }
    val filter = ScanFilter.Builder().setServiceUuid(
        ParcelUuid.fromString(BETTER_TOTP_UUID.toString())
    ).build()
    private val scanSettings = ScanSettings.Builder()
        .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
        .build()
    private val scanCallback = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult) {
            val indexQuery = scanResults.indexOfFirst { it.device.address == result.device.address }
            if (indexQuery != -1) { // A scan result already exists with the same address
                scanResults[indexQuery] = result
                scanResultAdapter.notifyItemChanged(indexQuery)
            } else {
                with(result.device) {
                    Log.i("ScanCallback", "Found BLE device! Name: ${name ?: "Unnamed"}, address: $address")
                }
                scanResults.add(result)
                scanResultAdapter.notifyItemInserted(scanResults.size - 1)
            }
        }

        override fun onScanFailed(errorCode: Int) {
            Log.e("ScanCallback", "onScanFailed: code $errorCode")
        }
    }
    private var isScanning = false
        set(value) {
            field = value
            runOnUiThread { findViewById<ImageButton>(R.id.scan_button).setImageResource(if (value) R.drawable.token_image_apple else R.drawable.token_image_adobe)  }
        }
    private val scanResults = mutableListOf<ScanResult>()
    private val scanResultAdapter: ScanResultAdapter by lazy {
        ScanResultAdapter(scanResults) {result ->
            // User tapped on a scan result
            if (isScanning) {
                stopBleScan()
            }
            with(result.device) {
                Log.w("ScanResultAdapter", "Connecting to $address")
                connectGatt(applicationContext, false, gattCallback)
            }
        }
    }
    private val gattCallback = object : BluetoothGattCallback() {
        override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
            val deviceAddress = gatt.device.address

            if (status == BluetoothGatt.GATT_SUCCESS) {
                if (newState == BluetoothProfile.STATE_CONNECTED) {
                    Log.w("BluetoothGattCallback", "Successfully connected to $deviceAddress")
                    bluetoothGatt = gatt
                    Handler(Looper.getMainLooper()).post {
                        bluetoothGatt?.discoverServices()
                    }
                } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                    Log.w("BluetoothGattCallback", "Successfully disconnected from $deviceAddress")
                    gatt.close()
                }
            } else {
                Log.w("BluetoothGattCallback", "Error $status encountered for $deviceAddress! Disconnecting...")
                gatt.close()
            }
        }
        lateinit var bluetoothGatt: BluetoothGatt

        override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
            with(gatt) {
                Log.w("BluetoothGattCallback", "Discovered ${services.size} services for ${device.address}")
                printGattTable() // See implementation just above this section
                // Consider connection setup as complete here
            }
        }
    }

    private fun BluetoothGatt.printGattTable() {
        if (services.isEmpty()) {
            Log.i("printGattTable", "No service and characteristic available, call discoverServices() first?")
            return
        }
        services.forEach { service ->
            val characteristicsTable = service.characteristics.joinToString(
                separator = "\n|--",
                prefix = "|--"
            ) { it.uuid.toString() }
            Log.i("printGattTable", "\nService ${service.uuid}\nCharacteristics:\n$characteristicsTable"
            )
        }
    }

    override fun onResume() {
        super.onResume()
        if (!bluetoothAdapter.isEnabled) {
            promptEnableBluetooth()
        }
    }

    private fun promptEnableBluetooth() {
        if (!bluetoothAdapter.isEnabled) {
            val enableBtIntent = Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE)
            startActivityForResult(enableBtIntent, ENABLE_BLUETOOTH_REQUEST_CODE)
        }
    }

    private fun startBleScan() {
        if (!hasRequiredRuntimePermissions()) {
            requestRelevantRuntimePermissions()
        } else {
            scanResults.clear()
            scanResultAdapter.notifyDataSetChanged()
            bleScanner.startScan(null, scanSettings, scanCallback)
            isScanning = true
        }
    }

    private fun stopBleScan() {
        bleScanner.stopScan(scanCallback)
        isScanning = false
    }

    private fun Activity.requestRelevantRuntimePermissions() {
        if (hasRequiredRuntimePermissions()) { return }
        when {
            Build.VERSION.SDK_INT < Build.VERSION_CODES.S -> {
                requestLocationPermission()
            }
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
                requestBluetoothPermissions()
            }
        }
    }

    private fun requestLocationPermission() {
        runOnUiThread {
            AlertDialog.Builder(this@MainActivity)
                .setTitle("Location permission required")
                .setMessage("Starting from Android M (6.0), the system requires apps to be granted " +
                        "location access in order to scan for BLE devices.")
                .setPositiveButton(android.R.string.ok,
                    DialogInterface.OnClickListener { dialog, which ->
                        ActivityCompat.requestPermissions(
                            this,
                            arrayOf(Manifest.permission.ACCESS_FINE_LOCATION),
                            RUNTIME_PERMISSION_REQUEST_CODE
                        )
                    }
                )
                .setIcon(android.R.drawable.ic_dialog_alert)
                .show()
        }
    }
    private fun requestBluetoothPermissions() {
        runOnUiThread {
            AlertDialog.Builder(this@MainActivity)
                .setTitle("Bluetooth permissions required")
                .setMessage("Starting from Android 12, the system requires apps to be granted " +
                        "Bluetooth access in order to scan for and connect to BLE devices.")
                .setPositiveButton(android.R.string.ok,
                    DialogInterface.OnClickListener { dialog, which ->
                        ActivityCompat.requestPermissions(
                            this,
                            arrayOf(
                                Manifest.permission.BLUETOOTH_SCAN,
                                Manifest.permission.BLUETOOTH_CONNECT
                            ),
                            RUNTIME_PERMISSION_REQUEST_CODE
                        )
                    }
                )
                .setIcon(android.R.drawable.ic_dialog_alert)
                .show()
        }
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        when (requestCode) {
            RUNTIME_PERMISSION_REQUEST_CODE -> {
                val containsPermanentDenial = permissions.zip(grantResults.toTypedArray()).any {
                    it.second == PackageManager.PERMISSION_DENIED &&
                            !ActivityCompat.shouldShowRequestPermissionRationale(this, it.first)
                }
                val containsDenial = grantResults.any { it == PackageManager.PERMISSION_DENIED }
                val allGranted = grantResults.all { it == PackageManager.PERMISSION_GRANTED }
                when {
                    containsPermanentDenial -> {
                        // TODO: Handle permanent denial (e.g., show AlertDialog with justification)
                        // Note: The user will need to navigate to App Settings and manually grant
                        // permissions that were permanently denied
                    }
                    containsDenial -> {
                        requestRelevantRuntimePermissions()
                    }
                    allGranted && hasRequiredRuntimePermissions() -> {
                        startBleScan()
                    }
                    else -> {
                        // Unexpected scenario encountered when handling permissions
                        recreate()
                    }
                }
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        onNewIntent(intent)

        binding = MainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        viewModel.migrateOldData()

        binding.tokenList.adapter = tokenListAdapter

        // Used GridlayoutManager to support tablet mode for multiple columns
        // Make sure one column has at least 320 DP
        val columns =  max(1, resources.configuration.screenWidthDp / 320)
        binding.tokenList.layoutManager = GridLayoutManager(this, columns)


        ItemTouchHelper(TokenTouchCallback(this, tokenListAdapter, otpTokenDatabase))
            .attachToRecyclerView(binding.tokenList)
        tokenListAdapter.registerAdapterDataObserver(tokenListObserver)

        lifecycleScope.launch {
            viewModel.getTokenList().collect { tokens ->
                tokenListAdapter.submitList(tokens)

                if (tokens.isEmpty()) {
                    binding.emptyView.visibility = View.VISIBLE
                    binding.tokenList.visibility = View.GONE
                } else {
                    binding.emptyView.visibility = View.GONE
                    binding.tokenList.visibility = View.VISIBLE
                }
            }
        }

        lifecycleScope.launch {
            viewModel.getAuthState().collect { authState ->
                if (authState == MainViewModel.AuthState.UNAUTHENTICATED) {
                    verifyAuthentication()
                }
            }
        }

        setSupportActionBar(binding.toolbar)

        binding.searchView.setOnQueryTextListener(object: SearchView.OnQueryTextListener, androidx.appcompat.widget.SearchView.OnQueryTextListener {
            override fun onQueryTextSubmit(query: String?): Boolean {
                viewModel.setTokenSearchQuery(query ?: "")
                return true
            }

            override fun onQueryTextChange(query: String?): Boolean {
                searchQuery = query ?: ""
                viewModel.setTokenSearchQuery(query ?: "")
                return true
            }

        })

        binding.scanButton.setOnClickListener {
            val context = applicationContext
            val intent = Intent(context, BleDevicesActivity::class.java)
            if (isScanning) {
                stopBleScan()
            } else {
                startBleScan()
            }
        }

        binding.addTokenFab.setOnClickListener {
            startActivity(Intent(this, ScanTokenActivity::class.java))
        }

        // Don't permit screenshots since these might contain OTP codes unless explicitly
        // launched with screenshot mode

        if (intent.extras?.getBoolean(SCREENSHOT_MODE_EXTRA) != true) {
            window.setFlags(
                WindowManager.LayoutParams.FLAG_SECURE,
                WindowManager.LayoutParams.FLAG_SECURE
            )
        }

        setupRecyclerView()
    }

    private fun setupRecyclerView() {
        binding.scanResultsRecyclerView.apply {
            adapter = scanResultAdapter
            layoutManager = LinearLayoutManager(
                this@MainActivity,
                RecyclerView.VERTICAL,
                false
            )
            isNestedScrollingEnabled = false
        }

        val animator = binding.scanResultsRecyclerView.itemAnimator
        if (animator is SimpleItemAnimator) {
            animator.supportsChangeAnimations = false
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        tokenListAdapter.unregisterAdapterDataObserver(tokenListObserver)
        lastSessionEndTimestamp = 0L;
    }

    override fun onStart() {
        super.onStart()

        viewModel.onSessionStart()
    }
    
    override fun onStop() {
        super.onStop()
        viewModel.onSessionStop()
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(R.menu.main, menu)
        this.menu = menu
        refreshOptionMenu()
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        when (item.itemId) {
            R.id.action_scan -> {
                startActivity(Intent(this, ScanTokenActivity::class.java))
                return true
            }

            R.id.action_add -> {
                startActivity(Intent(this, AddActivity::class.java))
                return true
            }

            R.id.action_import_json -> {
                performFileSearch(READ_JSON_REQUEST_CODE)
                return true
            }

            R.id.action_import_key_uri -> {
                performFileSearch(READ_KEY_URI_REQUEST_CODE)
                return true
            }

            R.id.action_export_json -> {
                createFile("application/json", "freeotp-backup","json", WRITE_JSON_REQUEST_CODE)
                return true
            }

            R.id.action_export_key_uri -> {
                createFile("text/plain", "freeotp-backup","txt", WRITE_KEY_URI_REQUEST_CODE)
                return true
            }

            R.id.use_dark_theme -> {
                settings.darkMode = !settings.darkMode
                if (settings.darkMode) {
                    AppCompatDelegate.setDefaultNightMode(AppCompatDelegate.MODE_NIGHT_YES)
                } else {
                    AppCompatDelegate.setDefaultNightMode(AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM)
                }
                recreate()
                return true
            }

            R.id.copy_to_clipboard -> {
                settings.copyToClipboard = !settings.copyToClipboard
                item.isChecked = settings.copyToClipboard
                refreshOptionMenu()
            }

            R.id.require_authentication -> {
                // Make sure we also verify authentication before turning on the settings

                if (!settings.requireAuthentication) {
                    viewModel.setAuthState(MainViewModel.AuthState.UNAUTHENTICATED)
                } else {
                    settings.requireAuthentication = false
                    viewModel.setAuthState(MainViewModel.AuthState.AUTHENTICATED)
                    refreshOptionMenu()
                }

                return true
            }

            R.id.action_about -> {
                startActivity(Intent(this, AboutActivity::class.java))
                return true
            }

            R.id.quit_and_lock -> {
                finish()
                return true
            }
        }

        return false
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)

        if (packageName == intent.extras?.getString(SHARE_FROM_PACKAGE_NAME_INTENT_EXTRA)) {
            Log.i(TAG, "Intent shared from the same package name. Ignoring the intent and do not add the token")
            return
        }

        val uri = intent.data
        if (uri != null) {
            lifecycleScope.launch {
                try {
                    otpTokenDatabase.otpTokenDao().insert(OtpTokenFactory.createFromUri(uri))
                } catch (e: Exception) {
                    Snackbar.make(binding.rootView, R.string.invalid_token_uri_received, Snackbar.LENGTH_SHORT)
                            .show()
                }
            }
        }
    }

    fun Context.hasPermission(permissionType: String): Boolean {
        return ContextCompat.checkSelfPermission(this, permissionType) ==
                PackageManager.PERMISSION_GRANTED
    }
    fun Context.hasRequiredRuntimePermissions(): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            hasPermission(Manifest.permission.BLUETOOTH_SCAN) &&
                    hasPermission(Manifest.permission.BLUETOOTH_CONNECT)
        } else {
            hasPermission(Manifest.permission.ACCESS_FINE_LOCATION)
        }
    }

    public override fun onActivityResult(requestCode: Int, resultCode: Int,
                                         resultData: Intent?) {
        super.onActivityResult(requestCode, resultCode, resultData)

        // TODO MRN maybe put this in the when statement below
        when (requestCode) {
            ENABLE_BLUETOOTH_REQUEST_CODE -> {
                if (resultCode != Activity.RESULT_OK) {
                    promptEnableBluetooth()
                }
            }
        }

        if (resultCode != Activity.RESULT_OK) {
            return
        }

        when (requestCode) {
            WRITE_JSON_REQUEST_CODE -> {
                lifecycleScope.launch {
                    val uri = resultData?.data ?: return@launch
                    importFromUtil.exportJsonFile(uri)
                    Snackbar.make(binding.rootView, R.string.export_succeeded_text, Snackbar.LENGTH_SHORT)
                            .show()
                }
            }

            READ_JSON_REQUEST_CODE -> {
                val uri = resultData?.data ?: return
                MaterialAlertDialogBuilder(this)
                        .setTitle(R.string.import_json_file)
                        .setMessage(R.string.import_json_file_warning)
                        .setIcon(R.drawable.alert)
                        .setPositiveButton(R.string.ok_text) { _: DialogInterface, _: Int ->
                            lifecycleScope.launch {
                                try {
                                    importFromUtil.importJsonFile(uri)
                                    Snackbar.make(binding.rootView, R.string.import_succeeded_text, Snackbar.LENGTH_SHORT)
                                            .show()
                                } catch (e: Exception) {
                                    Log.e(TAG, "Import JSON failed", e)
                                    Snackbar.make(binding.root, R.string.import_json_failed_text, Snackbar.LENGTH_SHORT)
                                            .show()
                                }
                            }

                        }
                        .setNegativeButton(R.string.cancel_text, null)
                        .show()
            }

            WRITE_KEY_URI_REQUEST_CODE -> {
                lifecycleScope.launch {
                    val uri = resultData?.data ?: return@launch
                    importFromUtil.exportKeyUriFile(uri)
                    Snackbar.make(binding.rootView, R.string.export_succeeded_text, Snackbar.LENGTH_SHORT)
                            .show()
                }
            }

            READ_KEY_URI_REQUEST_CODE -> {
                lifecycleScope.launch {
                    val uri = resultData?.data ?: return@launch
                    try {
                        importFromUtil.importKeyUriFile(uri)
                        Snackbar.make(binding.rootView, R.string.import_succeeded_text, Snackbar.LENGTH_SHORT)
                                .show()
                    } catch (e: Exception) {
                        Log.e(TAG, "Import Key uri failed", e)
                        Snackbar.make(binding.rootView, R.string.import_key_uri_failed_text, Snackbar.LENGTH_SHORT)
                                .show()
                    }
                }
            }
        }

    }

    /**
     * Fires an intent to spin up the "file chooser" UI and select an image.
     */
    private fun performFileSearch(requestCode: Int) {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT)
        intent.addCategory(Intent.CATEGORY_OPENABLE)
        intent.type = "*/*"

        try {
            startActivityForResult(intent, requestCode)
        } catch (e: ActivityNotFoundException) {
            Log.e(TAG, "Cannot find activity", e)
            Toast.makeText(applicationContext,
                    getString(R.string.launch_file_browser_failure), Toast.LENGTH_SHORT).show();
        }
    }

    private fun createFile(mimeType: String, fileName: String, fileExtension: String, requestCode: Int, appendTimestamp: Boolean = true) {
        val intent = Intent(Intent.ACTION_CREATE_DOCUMENT)

        // Filter to only show results that can be "opened", such as
        // a file (as opposed to a list of contacts or timezones).
        intent.addCategory(Intent.CATEGORY_OPENABLE)

        // Create a file with the requested MIME type.
        intent.type = mimeType
        intent.putExtra(Intent.EXTRA_TITLE, "$fileName${if(appendTimestamp) "_${dateFormatter.format(Date())}" else ""}.$fileExtension")

        try {
            startActivityForResult(intent, requestCode)
        } catch (e: ActivityNotFoundException) {
            Log.e(TAG, "Cannot find activity", e)
            Toast.makeText(applicationContext,
                    getString(R.string.launch_file_browser_failure), Toast.LENGTH_SHORT).show();
        }
    }

    private fun refreshOptionMenu() {
        this.menu?.findItem(R.id.use_dark_theme)?.isChecked = settings.darkMode
        this.menu?.findItem(R.id.copy_to_clipboard)?.isChecked = settings.copyToClipboard
        this.menu?.findItem(R.id.require_authentication)?.isChecked = settings.requireAuthentication
    }

    private fun verifyAuthentication() {
        val executor = ContextCompat.getMainExecutor(this)
        val biometricPrompt = BiometricPrompt(this, executor,
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationError(errorCode: Int,
                                                       errString: CharSequence) {
                        super.onAuthenticationError(errorCode, errString)
                        // Don't show error message toast if user pressed back button
                        if (errorCode != BiometricPrompt.ERROR_USER_CANCELED) {
                            Toast.makeText(applicationContext,
                                "${getString(R.string.authentication_error)} $errString", Toast.LENGTH_SHORT)
                                .show()
                        }

                        if (errorCode != BiometricPrompt.ERROR_NO_DEVICE_CREDENTIAL) {
                            finish()
                        }
                    }

                    override fun onAuthenticationSucceeded(
                            result: BiometricPrompt.AuthenticationResult) {
                        super.onAuthenticationSucceeded(result)
                        viewModel.setAuthState(MainViewModel.AuthState.AUTHENTICATED)

                        if (!settings.requireAuthentication) {
                            settings.requireAuthentication = true
                            refreshOptionMenu()
                        }
                    }

                    override fun onAuthenticationFailed() {
                        // Invalid authentication, e.g. wrong fingerprint. Android auth UI shows an
                        // error, so no need for FreeOTP to show one
                        super.onAuthenticationFailed()

                        Toast.makeText(applicationContext,
                            R.string.unable_to_authenticate, Toast.LENGTH_SHORT)
                            .show()
                    }
                })

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
                .setTitle(getString(R.string.authentication_dialog_title))
                .setSubtitle(getString(R.string.authentication_dialog_subtitle))
                .setAllowedAuthenticators(BiometricManager.Authenticators.DEVICE_CREDENTIAL or BiometricManager.Authenticators.BIOMETRIC_WEAK)
                .build()

        biometricPrompt.authenticate(promptInfo)
    }

    companion object {
        private val TAG = MainActivity::class.java.simpleName
        const val READ_JSON_REQUEST_CODE = 42
        const val WRITE_JSON_REQUEST_CODE = 43
        const val READ_KEY_URI_REQUEST_CODE = 44
        const val WRITE_KEY_URI_REQUEST_CODE = 45
        const val SCREENSHOT_MODE_EXTRA = "screenshot_mode"
        const val SHARE_FROM_PACKAGE_NAME_INTENT_EXTRA = "shareFromPackageName"
    }
}
