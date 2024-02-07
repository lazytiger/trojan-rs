package com.bmshi.mobiletrojan

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import com.google.gson.Gson

class MainActivity : WryActivity() {
    private external fun onError(typ: String);
    private lateinit var intent:Intent

    data class InitResponse(val path: String, val pnames: ArrayList<String>)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        instance = this
    }

    fun getInitData(): String {
        val path = filesDir.absolutePath
        val packageNames = ArrayList<String>()

        // Get the list of installed apps
        val installedApps = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            packageManager.getInstalledApplications(PackageManager.ApplicationInfoFlags.of(0L))
        } else {
            packageManager.getInstalledApplications(0)
        }

        // Iterate over the installed apps and get the package names
        for (appInfo in installedApps) {
            packageNames.add(appInfo.packageName)
        }
        val response = InitResponse(path, packageNames)
        val gson = Gson()
        return gson.toJson(response)
    }

    private val requestServiceLauncher =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { it ->
            doActivityResult(it.resultCode)
        }

    private fun prepare(intent:Intent, appName: String, aDns: String, aGateway: String) {
        intent.putExtra("app", appName)
        intent.putExtra("gateway", aGateway)
        intent.putExtra("dns", aDns)
    }
    fun startVpn(appName: String, aDns: String, aGateway: String) {
        val intent = VpnService.prepare(this)
        if (intent != null) {
            prepare(intent, appName, aDns, aGateway)
            requestServiceLauncher.launch(intent)
        } else {
            this.intent =  Intent(this, BnetService::class.java);
            prepare(this.intent, appName, aDns, aGateway)
            doActivityResult(RESULT_OK)
        }
    }

    fun stopVpn() {
        try {
            Logger.info("stopVpn called in MainActivity")
            val intent = Intent(BnetService.STOP_ACTION)
            intent.setPackage(packageName)
            sendBroadcast(intent)
        } catch (e: Exception) {
            Logger.warn(e.toString())
            onError("stopVpn")
        }
    }

    fun updateNotification(message: String) {
        try {
            if (message.isEmpty()) {
                notifyBuilder.setContentText("启动中")
            } else {
                val bigTextStyle = NotificationCompat.BigTextStyle()
                bigTextStyle.bigText(message)
                notifyBuilder.setContentText("运行中")
                notifyBuilder.setStyle(bigTextStyle)
            }
            if (ContextCompat.checkSelfPermission(
                    this,
                    Manifest.permission.POST_NOTIFICATIONS
                ) == PackageManager.PERMISSION_GRANTED
            ) {
                NotificationManagerCompat.from(this)
                    .notify(BnetService.NOTIFICATION_ID, notifyBuilder.build())
            } else {
                requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1)
            }
        } catch (e: Exception) {
            Logger.warn(e.toString())
            onError("updateNotification")
        }
    }

    private fun doActivityResult(resultCode: Int) {
        if (resultCode == RESULT_OK) {
            Logger.info("activity result is ok")
            ContextCompat.startForegroundService(this, this.intent)
        } else {
            Logger.warn("activity result is not ok")
            onError("startVpn")
        }
    }

    companion object {
        lateinit var notifyBuilder: NotificationCompat.Builder
        lateinit var instance: MainActivity
    }
}