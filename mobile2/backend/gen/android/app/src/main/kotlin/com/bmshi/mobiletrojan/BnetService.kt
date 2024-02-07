package com.bmshi.mobiletrojan

import android.app.NotificationManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Binder
import android.os.Build
import android.os.IBinder
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationChannelCompat
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat


class BnetService : VpnService() {
    private external fun onStart(fd: Int, record: Boolean)
    private external fun onStop()
    private external fun onNetworkChanged(available: Boolean)

    private val networkMonitorCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            setUnderlyingNetworks(arrayOf(network))
            onNetworkChanged(true)
            Logger.warn("$network is available now")
        }

        override fun onLost(network: Network) {
            setUnderlyingNetworks(arrayOf(null))
            onNetworkChanged(false)
            Logger.warn("network is lost now")
        }

        override fun onCapabilitiesChanged(
            network: Network,
            networkCapabilities: NetworkCapabilities
        ) {
            setUnderlyingNetworks(arrayOf(network))
        }
    }

    private var networkMonitorRunning = false
    private lateinit var vpnFd: ParcelFileDescriptor
    private var running = false;

    private val stopReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action == STOP_ACTION) {
                Logger.info("received stop intent")
                close()
            }
        }
    }

    private fun createNotificationBuilder(): NotificationCompat.Builder {
        return NotificationCompat.Builder(this, "bnet")
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setContentTitle("Bnet服务")
            .setContentText("连接中")
            .setSmallIcon(R.mipmap.ic_launcher)
            //.setContentIntent(pi)
            .setAutoCancel(false)
            .setOngoing(true)
            .setShowWhen(true)
            .setWhen(0L)
            .setSound(null)
    }

    override fun onCreate() {
        val filter = IntentFilter(STOP_ACTION)
        registerReceiver(stopReceiver, filter)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Logger.info("start vpn service now")
        val app = intent?.getStringExtra("app").toString();
        val dns = intent?.getStringExtra("dns").toString();
        val gateway = intent?.getStringExtra("gateway").toString();
        val record = intent?.getBooleanExtra("record", false)
        val notifyChannel =
            NotificationChannelCompat.Builder("bnet", NotificationManager.IMPORTANCE_LOW)
                .setName("bnet")
                .build()
        NotificationManagerCompat.from(this).createNotificationChannel(notifyChannel)
        val notifyBuilder = createNotificationBuilder()
        startForeground(NOTIFICATION_ID, notifyBuilder.build())
        MainActivity.notifyBuilder = notifyBuilder
        MainActivity.instance.updateNotification("")
        Thread(Runnable {
            for (bypass in arrayOf(
                R.array.bypass_china_24,
                R.array.bypass_china_16,
                R.array.bypass_private_route
            )) {
                try {
                    val builder = Builder()
                    val manager = getSystemService(CONNECTIVITY_SERVICE) as ConnectivityManager
                    val network = manager.activeNetwork
                    if (network != null) {
                        builder.setUnderlyingNetworks(arrayOf(network))
                    }
                    for (route in resources.getStringArray(bypass)) {
                        val parts = route.split("/")
                        builder.addRoute(parts[0], parts[1].toInt())
                    }
                    builder.addRoute("0.0.0.0", 0)
                        .addAddress(gateway, 30)
                        .setSession("bnet")
                        .setMtu(1500)
                        .setBlocking(false)
                    if (app != "") {
                        builder.addAllowedApplication(app)
                    } else {
                        builder.addDisallowedApplication(packageName)
                    }
                    if (dns != "") {
                        Logger.info("add dns server '$dns'")
                        builder.addDnsServer(dns)
                    }
                    var vpn = builder.establish()
                    if (vpn != null) {
                        startNetworkMonitor()
                        vpnFd = vpn
                        running = true;
                        onStart(vpn.fd, record ?: false)
                        break
                    } else {
                        Logger.error("establish vpn failed")
                        close()
                    }
                } catch (e: Exception) {
                    Logger.error("initialize vpn failed", e)
                    close()
                }
            }
        }).start()
        return super.onStartCommand(intent, flags, startId)
    }

    override fun onDestroy() {
        super.onDestroy()
        unregisterReceiver(stopReceiver)
        if (running) {
            close()
        }
    }

    fun close() {
        Logger.info("stop vpn now in TrojanProxy")
        onStop()
        stopNetworkMonitor()
        stopForeground(STOP_FOREGROUND_REMOVE)
        NotificationManagerCompat.from(this).deleteNotificationChannel("bnet")
        try {
            vpnFd.close()
            running = false;
        } catch (e: Exception) {
            Logger.info(e.toString())
        }
        stopSelf()
    }

    override fun onRevoke() {
        Logger.info("revoke vpn service now")
        if (running) {
            close()
        }
    }

    private fun startNetworkMonitor() {
        val cm = getSystemService(CONNECTIVITY_SERVICE) as ConnectivityManager
        val nrb = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED)
        if (Build.VERSION.SDK_INT == Build.VERSION_CODES.M) {
            nrb.removeCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
                .removeCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL)
        }
        val request = nrb.build()
        try {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
                cm.registerNetworkCallback(request, networkMonitorCallback)
            } else {
                cm.requestNetwork(request, networkMonitorCallback)
            }
            networkMonitorRunning = true
        } catch (se: SecurityException) {
            Logger.warn(se.toString())
        }
    }

    private fun stopNetworkMonitor() {
        val cm = getSystemService(CONNECTIVITY_SERVICE) as ConnectivityManager
        try {
            if (networkMonitorRunning) {
                cm.unregisterNetworkCallback(networkMonitorCallback)
                networkMonitorRunning = false
            }
        } catch (e: Exception) {
            Logger.info(e.toString())
        }
    }

    companion object {
        const val STOP_ACTION = "com.bmshi.mobiletrojan.BnetService.STOP_VPN"
        const val NOTIFICATION_ID = 285714
    }
}