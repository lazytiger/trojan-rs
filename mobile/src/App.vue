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
        trusted_dns: "8.8.8.8",
        untrusted_dns: "114.114.114.114",
        dns_cache_time: 600,
        log_level: "Error",
        speed_update_ms: 2000,
      },
      label: "开始",
      running: false,
      homeVisible: true,
      ladderVisible: false,
      showResult: false,
      domains: [],
      query: "",
      network_lost: false,
      process_exit: true,
    }
  },
  methods: {
    async start() {
      await invoke("save_data", {key: "config", value: JSON.stringify(this.config)});
      if (!this.running) {
        await invoke("start_vpn", {options: this.config});
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
        if (event.payload === "VpnStart") {
          this.running = true;
          this.process_exit = false;
          this.label = "停止";
        } else if (event.payload === "ProcessExit") {
          if (this.network_lost) {
            this.process_exit = true;
          } else if (this.running) {
            await invoke("start_process", {})
            this.label = "重启中";
          }
        } else if (event.payload === "VpnStop") {
          this.process_exit = true;
          this.running = false;
          this.label = "开始";
        } else if (event.payload === "NetworkAvailable") {
          if (this.process_exit && this.running) {
            await invoke("start_process", {})
            this.label = "网络重启中";
          }
          this.network_lost = false;
        } else if (event.payload === "NetworkLost") {
          this.label = "网络连接断开";
          this.network_lost = true;
        }
      });
      await appWindow.listen("update_speed", async (event) => {
        if (this.running) {
          this.label = '停止';
          await invoke("update_notification", {content: event.payload});
        }
      })
    },
    do_action() {
      if (this.label !== '开始' && this.label !== '停止') {
        return;
      }
      if (!this.running) {
        this.start();
      } else {
        this.stop();
      }
    },
    config_ok() {
      return this.config.hostname !== "" && this.config.password !== "" && (this.label === "开始" || this.label === "停止")
    },
    showHome() {
      this.homeVisible = true;
      this.ladderVisible = false;
    },
    showLadder() {
      this.ladderVisible = true;
      this.homeVisible = false;
    },
    async handleDomain(item) {
      if (item.id === -1) {
        await invoke("add_domain", {key: this.query});
      } else {
        for (let i = 0; i < this.domains.length; i++) {
          let domain = this.domains[i];
          if (domain.value === item.id) {
            await invoke("remove_domain", {key: domain.title});
            break;
          }
        }
      }
      await this.doQuery();
    },
    async doQuery() {
      let domains = await invoke("search_domain", {key: this.query});
      this.domains = [];
      for (let i = 0; i < domains.length; i++) {
        let domain = domains[i];
        this.domains.push({title: domain, value: i});
      }
      if (this.domains.length === 0) {
        this.domains.push({title: "未找到该域名，点击添加", value: -1});
      }
      this.showResult = this.domains.length > 0;
    }
  },
  async mounted() {
    let data = await invoke("load_data", {key: "config"});
    if (data !== "") {
      this.config = JSON.parse(data.toString());
      this.config.speed_update_ms = 2000;
    }
    await invoke("init_window", {logLevel: this.config.log_level});
    await this.init_listener();
  }
}
</script>

<template>
  <v-app>
    <v-main class="bg-grey-lighten-4">
      <v-toolbar
          color="blue"
          dark=true
      >
        <v-toolbar-title>Trojan客户端</v-toolbar-title>
        <v-spacer></v-spacer>
        <v-btn icon @click="showHome">
          <v-icon>mdi-home-edit-outline</v-icon>
        </v-btn>
        <v-btn icon @click="showLadder">
          <v-icon>mdi-ladder</v-icon>
        </v-btn>
      </v-toolbar>
      <div v-if="homeVisible">
        <v-container class="mx-auto" style="max-width: 480px;">
          <v-text-field v-model="config.hostname" :readonly="running" label="服务器域名"
                        variant="outlined"></v-text-field>
          <v-text-field v-model="config.password" :append-icon="show ? 'mdi-eye' : 'mdi-eye-off'"
                        :readonly="running" :type="show ? 'text' : 'password'" label="服务器密码"
                        variant="outlined" @click:append="show = !show"></v-text-field>
          <v-text-field v-model="config.trusted_dns" :readonly="running" label="可信DNS"
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
      </div>
      <div v-if="ladderVisible">
        <v-container class="mx-auto" style="max-width: 480px;">
          <v-row>
            <v-col>
              <v-text-field v-model="query" label="域名关键字"
                            variant="outlined"></v-text-field>
            </v-col>
            <v-col cols="2">
              <v-btn icon @click="doQuery">
                <v-icon>mdi-tab-search</v-icon>
              </v-btn>
            </v-col>
          </v-row>
          <div v-if="showResult">
            <v-list :items="domains" class="my-list" @click:select="handleDomain">
            </v-list>
          </div>
        </v-container>
      </div>
    </v-main>
  </v-app>
</template>

<style>
.my-list {
  background-color: #f5f5f5;
  padding: 10px;
  border: 1px solid #ccc;
}
</style>

