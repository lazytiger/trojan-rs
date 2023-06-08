<script>
import {invoke} from "@tauri-apps/api";
import {appWindow} from "@tauri-apps/plugin-window";

const VPN_PERMISSION = "android.permission.BIND_VPN_SERVICE";

export default {
  data() {
    return {
      show: false,
      config: {
        hostname: "",
        password: "",
        pool_size: 20,
        mtu: 1500,
        port: 443,
        trust_dns: "8.8.8.8",
        untrusted_dns: "114.114.114.114",
        dns_cache_time: 600,
        log_level: "Error",
      },
      label: "开始",
      running: false,
    }
  },
  methods: {
    async start() {
      await invoke("save_data", {key: "config", value: JSON.stringify(this.config)});
      if (!this.running) {
        await invoke("start_vpn", {option: this.config});
        this.label = "启动中";
      }
    },
    async stop() {
      if (this.running) {
        await invoke("stop_vpn", {});
      }
    },
    async init_listener() {
      await appWindow.listen("on_status_changed", async (event) => {
        if (event.payload === 1) {
          this.running = true;
          this.label = "停止";
        } else if (event.payload === 2) {
          await invoke("stop_vpn", {})
          this.label = "关闭中";
        } else if (event.payload === 3) {
          this.running = false;
          this.label = "开始";
        }
      });
      await appWindow.listen("update_speed", async (event) => {
        if (this.running) {
          await invoke("update_notification", {content: event.payload});
        }
      })
    },
    do_action() {
      if (this.label === '启动中' || this.label === '关闭中') {
        return;
      }
      if (!this.running) {
        this.start();
      } else {
        this.stop();
      }
    },
    config_ok() {
      return this.config.hostname !== "" && this.config.password !== ""
    }
  },
  async mounted() {
    let data = await invoke("load_data", {key: "config"});
    if (data !== "") {
      this.config = JSON.parse(data.toString());
    }
    await invoke("init_window", {logLevel: this.config.log_level});
    await this.init_listener();
  }
}
</script>

<template>
  <v-app>
    <v-main class="bg-grey-lighten-4">
      <v-container class="mx-auto" style="max-width: 480px;">
        <v-text-field v-model="config.hostname" :readonly="running" label="服务器域名"
                      variant="outlined"></v-text-field>
        <v-text-field v-model="config.password" :append-icon="show ? 'mdi-eye' : 'mdi-eye-off'"
                      :readonly="running" :type="show ? 'text' : 'password'" label="服务器密码"
                      variant="outlined" @click:append="show = !show"></v-text-field>
        <v-text-field v-model="config.trust_dns" :readonly="running" label="可信DNS"
                      variant="outlined"></v-text-field>
        <v-text-field v-model="config.untrusted_dns" :readonly="running" label="不可信DNS"
                      variant="outlined"></v-text-field>
        <v-combobox v-model="config.log_level"
                    :items="['Trace', 'Debug', 'Info', 'Warn', 'Error', 'Off']"
                    :readonly="running"
                    label="日志级别" variant="solo"
        ></v-combobox>
        <v-slider v-model="config.pool_size" :readonly="running" label="连接池大小" max="20" min="0" step="1">
          <template v-slot:append>
            <v-text-field
                v-model="config.pool_size"
                :readonly="running"
                density="compact"
                hide-details
                single-line
                style="width: 70px"
                type="number"
            ></v-text-field>
          </template>
        </v-slider>
        <v-btn :disabled="!config_ok()" block="" color="blue" size="x-large" @click="do_action">{{ label }}</v-btn>
      </v-container>
    </v-main>
  </v-app>
</template>

