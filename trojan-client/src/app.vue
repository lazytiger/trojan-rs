<script>

import {invoke} from "@tauri-apps/api/core";
import {attachConsole, info} from "@tauri-apps/plugin-log";
import {getCurrentWebviewWindow} from "@tauri-apps/api/webviewWindow";
const appWindow = getCurrentWebviewWindow()

attachConsole();

async function update_speed() {
  await invoke("update_speed", {});
}

export default {
  data() {
    return {
      show: false,
      config: {
        iface_name: "trojan",
        server_domain: "",
        server_auth: "",
        log_level: "2",
        pool_size: 20,
        enable_dns: true,
        dns_listen: "",
        trust_dns: "",
      },
      label: "开始",
      running: false,
      homeVisible: true,
      domainVisible: false,
      domains: [],
      query: "",
      showResult: false,
    }
  },
  methods: {
    async init() {
      this.config = await invoke("init", {});
      setInterval(() => {
        update_speed();
      }, 1000);
    },
    start() {
      info("start trojan now");
      invoke("start", {"config": this.config});
    },
    is_config_ok() {
      return this.check_ipv4(this.config.dns_listen) === true &&
          this.check_ipv4(this.config.trust_dns) === true;
    },
    stop() {
      info("stop trojan now");
      invoke("stop", {});
    },
    showHome() {
      this.homeVisible = true;
      this.domainVisible = false;
    },
    showDomain() {
      this.domainVisible = true;
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
    },
    check_ipv4(s) {
      let ipv4_regex = /^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}$/gm;
      if (ipv4_regex.test(s)) {
        return true;
      } else {
        return "非法的ipv4地址";
      }
    },
    async update_state() {
      appWindow.listen("state-update", async (event) => {
        await info("event:state-update, label:" + event.windowLabel + ", payload:" + event.payload);
        if (event.payload) {
          this.label = "停止";
          this.running = true;
        } else {
          this.label = "开始";
          this.running = false;
        }
      });
    },
    do_action() {
      if (!this.running) {
        this.start();
      } else {
        this.stop();
      }
    }
  },
  mounted() {
    this.init();
    this.update_state();
  }
}


</script>

<template>
  <v-app>
    <v-main class="bg-grey-lighten-4">
      <v-toolbar color="blue" dark=true>
        <v-toolbar-title>Trojan客户端</v-toolbar-title>
        <v-spacer></v-spacer>
        <v-btn icon @click="showHome">
          <v-icon>mdi-home-edit-outline</v-icon>
        </v-btn>
        <v-btn icon @click="showDomain">
          <v-icon>mdi-ladder</v-icon>
        </v-btn>
      </v-toolbar>
      <div v-if="homeVisible">
      <v-container class="mx-auto" style="max-width: 480px;">
        <v-text-field v-model="config.iface_name" :readonly="running" label="虚拟网卡名"
                      variant="outlined"></v-text-field>
        <v-text-field v-model="config.server_domain" :readonly="running" label="服务器域名"
                      variant="outlined"></v-text-field>
        <v-text-field v-model="config.server_auth" :append-icon="show ? 'mdi-eye' : 'mdi-eye-off'"
                      :readonly="running" :type="show ? 'text' : 'password'" label="服务器密码"
                      variant="outlined" @click:append="show = !show"></v-text-field>
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
        <v-container class="rounded-xl, border">
          <v-checkbox v-model="config.enable_dns" :readonly="running"
                      label="信任DNS" @click="config.enable_dns=!config.enable_dns"></v-checkbox>
          <div v-if="config.enable_dns">
            <v-text-field v-model="config.dns_listen" :readonly="running" :rules="[check_ipv4]"
                          label="监听地址" variant="outlined"></v-text-field>
            <v-text-field v-model="config.trust_dns" :readonly="running" :rules="[check_ipv4]"
                          label="可信DNS地址" variant="outlined"></v-text-field>
          </div>
        </v-container>
        <v-btn :disabled="!is_config_ok()" block color="blue" size="x-large" @click="do_action">{{ label }}</v-btn>
      </v-container>
      </div>
      <div v-if="domainVisible">
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
